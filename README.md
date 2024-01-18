# Malware Detection Model

> NOTE: The model was trained on a small dataset, which may affect the quality of
> classification of new files.
>
> The author is not responsible for damages caused by misclassification.

A malware detection model using dynamic analysis data. The model works for Windows
operating system files: exe, dll, pe.


## Dependencies

We create a virtual environment that will be used to install libraries:

```shell
python -m venv venv
source venv/bin/activate
```

Next, you need to install Poetry as a library version control system:

```shell
pip install -U pip
pip install poetry
```

Next, install all the necessary libraries:

```shell
poetry install
```


## Service

First you need to launch a broker (Apache Kafka) and a database to store the result (Redis).
Also, the Kafka-UI server will be launched for Kafka (if you do not need it, you can delete/comment
out the corresponding lines of the _docker-compose_ file).

```shell
docker-compose up -d
```

Next you need to create topics in Kafka for the service to work:

| Topic                                       | Description                                                                                       |
|---------------------------------------------|---------------------------------------------------------------------------------------------------|
| `malware-detection.task.available`          | Available tasks for the classification system. The API server uses this topic to create tasks.    |
| `malware-detection.task.sha256-calculation` | Tasks for calculating a hash for further obtaining a report.                                      |
| `malware-detection.task.receiving-report`   | Tasks for obtaining dynamic analysis reports.                                                     |                                                                                                         |
| `malware-detection.task.classification`     | File classification tasks using a malware detection model.                                        |
| `malware-detection.task.completed`          | Completed tasks. They are processed by a method that generates the result and places it in Redis. |

> To create topics, you can use Kafka-UI.


Next, the workers of the classification system are launched. The main pipeline worker is launched
with the following command:

```shell
python -m faust -A detectify.tasks.core worker -l info --without-web
```


To launch the model worker, use the following command:

```shell
python -m faust -A detectify.tasks.classifier worker -l info --without-web
```

> The model is launched by a separate worker, since if everything is launched together, the model will block all asynchronous code.


### API Server

To launch the API, use the following command:

```shell
python -m uvicorn apiserver.main:app --host=127.0.0.1 --port=8100
```


### Gradio (Soon...)

To launch the Gradio demo, use the following command:

```shell
python -m uvicorn detectify.app_web:app --host=127.0.0.1 --port=8100
```


## Model v1.2.1

The model was trained based on the dataset: [DikeDataset](https://github.com/iosifache/DikeDataset)

Model weights (v1.1.1): [Google Drive](https://drive.google.com/file/d/1gV8ZzvViB2iAro3-1g_Pi-bBxJ1kW2ax/view?usp=sharing)

The architecture of the model consists of two models: ResNet-50 and Longformer
([kazzand/ru-longformer-tiny-16384](https://huggingface.co/kazzand/ru-longformer-tiny-16384)). Next, the outputs
of the models are concatenated and fed into a linear layer, followed by a linear layer of dimension 2.

For the ResNet-50 Model, an image is built from the bytes of the file, thereby obtaining a single-channel image.

The language model uses file run report data. This data is obtained from VirusTotal, after which the reports are
parsed into the required form. Also, at this stage, unnecessary data is filtered.

Due to the limited size of the language model context, the sliding window method is used. The input text of the
model is divided into blocks, the size of which does not exceed the maximum number of tokens, with an overlap of
50% of the maximum number of tokens. Next, each chunk of text along with an image is fed into the model, after which
the best result is selected with the priority of the malicious class.

### Classification Report

Accuracy: 0.999183

F1-Macro: 0.999500

|        label | precision | recall | f1-score | support |
|-------------:|----------:|-------:|---------:|--------:|
|       benign |      1.00 |   1.00 |     1.00 |     224 |
|      malware |      1.00 |   1.00 |     1.00 |    1001 |
|              |           |        |          |         |
|     accuracy |           |        |     1.00 |    1225 |
|    macro avg |      1.00 |   1.00 |     1.00 |    1225 |
| weighted avg |      1.00 |   1.00 |     1.00 |    1225 |

