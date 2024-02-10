import json
import hashlib
import asyncio

import aiohttp
import aiofiles
from sqlalchemy.future import select

from detectify.db import AnalysisInfo as AnalysisInfoTable
from detectify.tasks.core import app
from detectify.core.task import TaskStatus
from .topics import (
    topic_available_tasks,
    topic_sha256_calculations,
    topic_receiving_reports,
    topic_classifications,
    topic_completed_tasks,
)


@app.agent(topic_available_tasks)
async def available_tasks_handler(tasks):
    """Stream processing of new tasks."""
    async for task in tasks:
        await app.redis_client.hset(task.task_id, 'status', TaskStatus.STARTED)
        await topic_sha256_calculations.send(value=task)


@app.agent(topic_sha256_calculations)
async def sha256_calculations_handler(tasks):
    """Stream of hash calculations for files."""
    async for task in tasks:
        await app.redis_client.hset(
            name=task.task_id,
            mapping={
                'meta': 'HASH calculation',
                'status': TaskStatus.PROGRESS,
            }
        )

        hash_instance = hashlib.sha256()
        buffer = bytearray(1024 * 128)
        buffer_view = memoryview(buffer)
        with open(task.file_path, 'rb', buffering=0) as file:
            while n := file.readinto(buffer_view):
                hash_instance.update(buffer_view[:n])

        task.sha256 = hash_instance.hexdigest()
        await topic_receiving_reports.send(value=task)


@app.agent(topic_receiving_reports, concurrency=1)
async def receiving_reports_handler(tasks):
    """Stream receiving file reports."""
    async for task in tasks:
        await app.redis_client.hset(
            name=task.task_id,
            mapping={
                'meta': 'Receiving report',
                'status': TaskStatus.PROGRESS,
            }
        )
        # Search for a report in the database.
        async with app.database_async_session() as session:
            query = select(AnalysisInfoTable).where(AnalysisInfoTable.sha256 == task.sha256)
            result = await session.execute(query)
            analysis_info = result.scalar_one_or_none()

        if analysis_info is not None:
            task.report_path = analysis_info.report_path
            await topic_classifications.send(value=task)
            continue
        
        # If the report is not found, then the report is obtained using the API from VirusTotal.
        async with aiohttp.ClientSession() as session:
            file_report = {}
            headers = {'x-apikey': app.config.virustotal_apikey}
            url = f'https://www.virustotal.com/api/v3/files/{task.sha256}'
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    reponse_text = await response.text()
                    await app.redis_client.hset(
                        name=task.task_id,
                        mapping={
                            'meta': f'Error: {reponse_text}',
                            'status': TaskStatus.FAILURE,
                        }
                    )
                    continue
                
                json_body = await response.json()
                file_report['files'] = json_body
            # Sleep is needed because the free API allows 4 requests per minute.
            await asyncio.sleep(15)
            url = f'https://www.virustotal.com/api/v3/files/{task.sha256}/behaviours'
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    reponse_text = await response.text()
                    await app.redis_client.hset(
                        name=task.task_id,
                        mapping={
                            'meta': f'Error: {reponse_text}',
                            'status': TaskStatus.FAILURE,
                        }
                    )
                    continue
                json_body = await response.json()
                file_report['files_behaviours'] = json_body
            await asyncio.sleep(15)
        report_path = app.reports_cache_dir / f'{task.sha256}.json'
        async with aiofiles.open(report_path, 'w') as file:
            await file.write(json.dumps(file_report))
        task.report_path = str(report_path)
        await topic_classifications.send(value=task)


@app.agent(topic_completed_tasks)
async def completed_tasks_handler(tasks):
    """Stream processing of completed tasks."""
    async for task in tasks:
        result = {
            'label': task.model_label,
            'score': task.model_score,
        }
        await app.redis_client.hset(
            name=task.task_id,
            mapping={
                'meta': 'Completed task',
                'status': TaskStatus.SUCCESS,
                'result': json.dumps(result),
            }
        )
        # We save the classification result and the path to the report and file.
        async with app.database_async_session() as session:
            query = select(AnalysisInfoTable).filter(AnalysisInfoTable.sha256 == task.sha256)
            existing_info = await session.execute(query)
            existing_info = existing_info.scalars().first()
            if existing_info:
                continue
            analysis_info = AnalysisInfoTable(
                sha256=task.sha256,
                report_path=task.report_path,
                file_path=task.file_path,
                score=task.model_score,
                label=task.model_label,
            )
            session.add(analysis_info)
            await session.commit()
        
