# Malware Detection Model

> NOTE: The model was trained on a small dataset, which may affect the quality of
> classification of new files.
>
> The author is not responsible for damages caused by misclassification.

A malware detection model using dynamic analysis data. The model works for Windows
operating system files: exe, dll, pe.

## Demo

First you need to start the broker (RabbitMQ) and store (Redis) for the result:

```shell
docker-compose up -d
```

Next you need to start the worker:

```shell
python -m celery -A src.celery worker --loglevel=info --pool=solo
```

After this, you can select an environment to interact with the model.


### API

To launch the API, use the following command:

```shell
python -m uvicorn src.main:app --host=127.0.0.1 --port=8100
```


### Gradio

Coming soon...


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

