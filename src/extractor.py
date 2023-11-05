import json
from pathlib import Path


class VirusTotalFeatureExtractor:
    def __init__(
            self,
            files_report: dict,
            files_behaviours_report: dict,
    ):
        self._files_report = files_report
        self._sandbox_reports = {}

        for _report in files_behaviours_report.get('data', []):
            sandbox_name = _report['attributes']['sandbox_name']
            self._sandbox_reports[sandbox_name] = _report

    @staticmethod
    def from_json(file_path: Path):
        with open(file_path, 'r') as file:
            data = json.load(file)

        return VirusTotalFeatureExtractor(
            files_report=data['files'],
            files_behaviours_report=data['files_behaviours']
        )

    @property
    def type_tags(self):
        value = (
            self._files_report.get('data', {})
                              .get('attributes', {})
                              .get('type_tags', None)
        )
        return value

    @property
    def type_tag(self):
        value = (
            self._files_report.get('data', {})
                              .get('attributes', {})
                              .get('type_tag', None)
        )
        return value

    @property
    def detectiteasy(self):
        value = (
            self._files_report.get('data', {})
                              .get('attributes', {})
                              .get('detectiteasy', None)
        )
        return value

    @property
    def type_extension(self):
        value = (
            self._files_report.get('data', {})
                              .get('attributes', {})
                              .get('type_extension', None)
        )
        return value

    @property
    def import_list(self):
        value = (
            self._files_report.get('data', {})
                              .get('attributes', {})
                              .get('pe_info', {})
                              .get('import_list', None)
        )
        return value

    @property
    def magic(self):
        value = (
            self._files_report.get('data', {})
                              .get('attributes', {})
                              .get('magic', None)
        )
        return value

    @property
    def mitre_attack_techniques(self):
        report = {}
        sandboxes = ['CAPE Sandbox', 'Lastline']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('mitre_attack_techniques', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def signature_matches(self):
        report = {}

        value = (
            self._sandbox_reports.get('CAPA', {})
                                 .get('attributes', {})
                                 .get('signature_matches', None)
        )
        if value is not None:
            report['CAPA'] = value

        return report if report else None

    @property
    def registry_keys_opened(self):
        report = {}
        sandboxes = ['CAPE Sandbox', 'Rising MOVES', 'Tencent HABO', 'VirusTotal Jujubox']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('registry_keys_opened', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def command_executions(self):
        report = {}
        sandboxes = ['CAPE Sandbox', 'Lastline', 'Microsoft Sysinternals', 'Rising MOVES',
                     'Tencent HABO', 'VirusTotal Cuckoofork']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('command_executions', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def registry_keys_set(self):
        report = {}
        sandboxes = ['CAPE Sandbox', 'Lastline', 'Microsoft Sysinternals', 'Rising MOVES',
                     'Tencent HABO', 'VirusTotal Jujubox', 'VirusTotal Observer']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('registry_keys_set', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def mutexes_opened(self):
        report = {}
        sandboxes = ['CAPE Sandbox', 'Lastline', 'Tencent HABO', 'VirusTotal Cuckoofork']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('mutexes_opened', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def dns_lookups(self):
        report = {}
        sandboxes = ['CAPE Sandbox', 'Lastline', 'Microsoft Sysinternals', 'Tencent HABO',
                     'VirusTotal Cuckoofork', 'VirusTotal Jujubox']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('dns_lookups', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def calls_highlighted(self):
        report = {}
        sandboxes = ['CAPE Sandbox', 'VirusTotal Jujubox']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('calls_highlighted', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def mutexes_created(self):
        report = {}
        sandboxes = ['CAPE Sandbox', 'Lastline', 'Rising MOVES', 'Tencent HABO',
                     'VirusTotal Cuckoofork', 'VirusTotal Jujubox']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('mutexes_created', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def processes_tree(self):
        report = {}
        sandboxes = ['CAPE Sandbox', 'Lastline', 'Microsoft Sysinternals',
                     'Tencent HABO', 'VirusTotal Jujubox']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('processes_tree', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def modules_loaded(self):
        report = {}
        sandboxes = ['CAPE Sandbox', 'Lastline', 'Microsoft Sysinternals', 'Tencent HABO',
                     'VirusTotal Cuckoofork', 'VirusTotal Jujubox']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('modules_loaded', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def processes_created(self):
        report = {}
        sandboxes = ['Lastline', 'Microsoft Sysinternals', 'Rising MOVES', 'Tencent HABO',
                     'VirusTotal Cuckoofork', 'VirusTotal Jujubox']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('processes_created', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def files_attribute_changed(self):
        report = {}

        value = (
            self._sandbox_reports.get('Lastline', {})
                                 .get('attributes', {})
                                 .get('files_attribute_changed', None)
        )
        if value is not None:
            report['Lastline'] = value

        return report if report else None

    @property
    def registry_keys_deleted(self):
        report = {}
        sandboxes = ['Lastline', 'Tencent HABO']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('registry_keys_deleted', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def services_started(self):
        report = {}

        value = (
            self._sandbox_reports.get('Lastline', {})
                                 .get('attributes', {})
                                 .get('services_started', None)
        )
        if value is not None:
            report['Lastline'] = value

        return report if report else None

    @property
    def ip_traffic(self):
        report = {}
        sandboxes = ['Microsoft Sysinternals', 'VirusTotal Cuckoofork', 'VirusTotal Jujubox']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('ip_traffic', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def processes_terminated(self):
        report = {}
        sandboxes = ['Microsoft Sysinternals', 'Tencent HABO', 'VirusTotal Jujubox']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('processes_terminated', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def files_deleted(self):
        report = {}
        sandboxes = ['Microsoft Sysinternals', 'Rising MOVES']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('files_deleted', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def files_dropped(self):
        report = {}
        sandboxes = ['Microsoft Sysinternals', 'VirusTotal Jujubox']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('files_dropped', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def files_copied(self):
        report = {}
        sandboxes = ['Rising MOVES', 'VirusTotal Cuckoofork']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('files_copied', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def files_written(self):
        report = {}
        sandboxes = ['Rising MOVES', 'Tencent HABO', 'VirusTotal Cuckoofork',
                     'VirusTotal Jujubox', 'VirusTotal Observer']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('files_written', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def http_conversations(self):
        report = {}
        sandboxes = ['Rising MOVES', 'Tencent HABO']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('http_conversations', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def files_opened(self):
        report = {}
        sandboxes = ['Rising MOVES', 'Tencent HABO', 'VirusTotal Cuckoofork', 'VirusTotal Jujubox']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('files_opened', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def processes_injected(self):
        report = {}
        sandboxes = ['Tencent HABO', 'VirusTotal Cuckoofork']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('processes_injected', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def services_opened(self):
        report = {}
        sandboxes = ['Tencent HABO', 'VirusTotal Cuckoofork']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('services_opened', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def signals_hooked(self):
        report = {}
        sandboxes = ['VirusTotal Cuckoofork']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('signals_hooked', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None

    @property
    def windows_searched(self):
        report = {}
        sandboxes = ['VirusTotal Cuckoofork']

        for sandbox in sandboxes:
            value = (
                self._sandbox_reports.get(sandbox, {})
                                     .get('attributes', {})
                                     .get('windows_searched', None)
            )
            if value is not None:
                report[sandbox] = value

        return report if report else None
