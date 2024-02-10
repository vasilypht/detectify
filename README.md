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

| Topic                           | Description                                                                                       |
|---------------------------------|---------------------------------------------------------------------------------------------------|
| `detectify.available-tasks`     | Available tasks for the classification system. The API server uses this topic to create tasks.    |
| `detectify.sha256-calculations` | Tasks for calculating a hash for further obtaining a report.                                      |
| `detectify.receiving-reports`   | Tasks for obtaining dynamic analysis reports.                                                     |
| `detectify.classifications`     | File classification tasks using a malware detection model.                                        |
| `detectify.completed-tasks`     | Completed tasks. They are processed by a method that generates the result and places it in Redis. |

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


## Model v2.0.0

The model was trained based on the (40k files) dataset: [PE Malware Machine Learning Dataset](https://practicalsecurityanalytics.com/pe-malware-machine-learning-dataset/)

Model weights: ...

The architecture of the model consists of two models: ViT ([WinKawaks/vit-small-patch16-224](https://huggingface.co/WinKawaks/vit-small-patch16-224))
and Longformer ([kazzand/ru-longformer-tiny-16384](https://huggingface.co/kazzand/ru-longformer-tiny-16384)).
Next, the outputs of the models are concatenated and fed into a linear layer, followed by a linear layer of dimension 2.

For the ViT Model, an image is built from the bytes of the file (including .TEXT and .DATA), thereby obtaining
a three-channel image.

The language model uses file run report data. This data is obtained from VirusTotal, after which the reports are
parsed into the required form. Also, at this stage, unnecessary data is filtered.

Due to the limited size of the language model context, the sliding window method is used. The input text of the
model is divided into blocks, the size of which does not exceed the maximum number of tokens, with an overlap of
50% of the maximum number of tokens. Next, each chunk of text along with an image is fed into the model, after which
the best result is selected with the priority of the malicious class.

### Classification Report

Accuracy: 0.9521

F1 macro: 0.9557

|        label | precision | recall | f1-score | support |
|-------------:|----------:|-------:|---------:|--------:|
|       benign |      0.95 |   0.94 |     0.95 |    3377 |
|      malware |      0.95 |   0.96 |     0.96 |    3933 |

