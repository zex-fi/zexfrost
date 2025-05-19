from pydantic_settings import BaseSettings


class BaseApplicationSettings(BaseSettings):
    model_config = {"env_file": ".env"}
