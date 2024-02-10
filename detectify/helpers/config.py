from omegaconf import (
    DictConfig,
    OmegaConf,
)

from detectify.const import CONFIG_PATHS_TO_SEARCH


def load_config(filename: str) -> DictConfig:
    for path in CONFIG_PATHS_TO_SEARCH:
        config_path = path / filename
        if config_path.exists():
            break
    else:
        raise ValueError(f"Config {filename} not found!")
    
    config = OmegaConf.load(config_path)
    OmegaConf.set_readonly(config, True)
    return config
    
