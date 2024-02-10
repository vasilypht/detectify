from pathlib import Path
from typing import Union

import torch
import pefile
from langchain.text_splitter import RecursiveCharacterTextSplitter
from transformers import (
    PreTrainedModel,
    PretrainedConfig,
    ViTConfig,
    ViTModel,
    LongformerConfig,
    LongformerModel,
    AutoTokenizer,
    AutoImageProcessor,
)


TOKENIZER_OPTIONS = {
    'add_special_tokens': True,
    'return_attention_mask': True,
    'max_length': 10_240,
    'padding': 'max_length',
    'truncation': True,
    'return_tensors': 'pt',
}


class ViTLongformerConfig(PretrainedConfig):
    ...


class ViTLongformerModel(PreTrainedModel):
    config_class = ViTLongformerConfig
    
    def __init__(self, config: ViTLongformerConfig) -> None:
        super(ViTLongformerModel, self).__init__(config)
        self.config = config
        vit_config = ViTConfig.from_dict(config.vit_config)
        self.vit_model = ViTModel(vit_config, add_pooling_layer=False)
        longformer_config = LongformerConfig.from_dict(config.longformer_config)
        self.longformer_model = LongformerModel(longformer_config)
        in_features = self.vit_model.config.hidden_size + self.longformer_model.config.hidden_size
        self.classifier = torch.nn.Sequential(
            torch.nn.Dropout(0.2),
            torch.nn.Linear(in_features, self.config.hidden_size),
            torch.nn.BatchNorm1d(self.config.hidden_size),
            torch.nn.ReLU(),
            torch.nn.Dropout(0.2),
            torch.nn.Linear(self.config.hidden_size, self.config.num_labels),
        )
        self.init_weights()

    def forward(
            self,
            longformer_input_ids,
            longformer_attention_mask,
            longformer_global_attention_mask,
            vit_pixel_values,
    ):
        vit_embds = self.vit_model(pixel_values=vit_pixel_values).last_hidden_state[:,0,:]
        longformer_embds = self.longformer_model(
            input_ids=longformer_input_ids,
            attention_mask=longformer_attention_mask,
            global_attention_mask=longformer_global_attention_mask,
        ).last_hidden_state[:,0,:]
        concated_outputs = torch.concat([vit_embds.flatten(start_dim=1), longformer_embds.flatten(start_dim=1)], dim=1)
        logits = self.classifier(concated_outputs)
        return logits


class ViTLongformerPipeline:
    def __init__(
            self,
            model_path: Union[Path, str],
            device: Union[str, torch.device] = torch.device('cpu'),
            tokenizer_options: dict = TOKENIZER_OPTIONS,
    ) -> None:
        self.device = device if torch.cuda.is_available() else torch.device('cpu')
        self.model = ViTLongformerModel.from_pretrained(model_path)
        self.model = self.model.to(self.device)
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.tokenizer_options = tokenizer_options
        self.image_processor = AutoImageProcessor.from_pretrained(model_path)
        self.text_splitter = RecursiveCharacterTextSplitter.from_huggingface_tokenizer(
            tokenizer=self.tokenizer,
            chunk_size=10_240,
            chunk_overlap=3_072,
        )
    
    @torch.inference_mode()
    def __call__(self, file_path: Union[str, Path], corpus: str) -> dict:
        with open(file_path, 'rb') as _file:
            data_ch1 = list(_file.read(224 * 224))
            data_ch2 = data_ch1.copy()
            data_ch3 = data_ch1.copy()

        try:
            pe = pefile.PE(file_path)
            for section in pe.sections:
                if section.Name.startswith(b'.text'):
                    data_ch2 = list(pe.__data__[section.get_PointerToRawData_adj():224*224])
                    break
            for section in pe.sections:
                if section.Name.startswith(b'.data'):
                    data_ch3 = list(pe.__data__[section.get_PointerToRawData_adj():224*224])
                    break
        except:
            pass
        for data in (data_ch1, data_ch2, data_ch3):
            padding = [0] * (224*224 - len(data))
            data.extend(padding)

        img = torch.stack(
            [
                torch.reshape(input=torch.tensor(data_ch1, dtype=torch.uint8), shape=(1, 224, 224)),
                torch.reshape(input=torch.tensor(data_ch2, dtype=torch.uint8), shape=(1, 224, 224)),
                torch.reshape(input=torch.tensor(data_ch3, dtype=torch.uint8), shape=(1, 224, 224)),
            ],
            dim=1
        )
        pixel_values = self.image_processor(img, return_tensors="pt").pixel_values
        report_chunks = self.text_splitter.split_text(corpus)
        stats = []
        for chunk in report_chunks:
            inputs = self.tokenizer(chunk, **self.tokenizer_options)
            global_attention_mask = [
                [1 if token_id == self.tokenizer.cls_token_id else 0 for token_id in input_ids]
                for input_ids in inputs["input_ids"]
            ]
            inputs["global_attention_mask"] = torch.tensor(global_attention_mask)
    
            model_input = dict(
                longformer_input_ids=inputs['input_ids'],
                longformer_attention_mask=inputs['attention_mask'],
                longformer_global_attention_mask=inputs['global_attention_mask'],
                vit_pixel_values=pixel_values
            )
            model_input = {key: value.to(self.device) for key, value in model_input.items()}
            max_elements, max_indices = (
                self.model(**model_input)
                    .cpu()
                    .softmax(-1)
                    .max(-1)
            )
            stats.append( (max_indices[0].item(), max_elements[0].item()) )
        
        malware_scores= []
        benign_scores = []
        for label_id, score in stats:
            if label_id == 0:
                benign_scores.append(score)
            elif label_id == 1:
                malware_scores.append(score)
            else:
                raise NotImplementedError()
        if malware_scores:
            return {'label_id': 1, 'score': max(malware_scores)} 
        return {'label_id': 0, 'score': max(benign_scores)}  
    