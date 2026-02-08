"""Unit tests for AI provider detection and configuration"""

from run_ai_audit import detect_ai_provider, get_model_name


class TestAIProviders:
    """Test suite for AI provider functionality"""

    def test_detect_anthropic(self, mock_config):
        """Test Anthropic provider detection"""
        config = mock_config.copy()
        config["anthropic_api_key"] = "sk-ant-test"
        config["ai_provider"] = "auto"

        provider = detect_ai_provider(config)
        assert provider == "anthropic"

    def test_detect_openai(self, mock_config):
        """Test OpenAI provider detection"""
        config = mock_config.copy()
        config["anthropic_api_key"] = ""
        config["openai_api_key"] = "sk-test"
        config["ai_provider"] = "auto"

        provider = detect_ai_provider(config)
        assert provider == "openai"

    def test_detect_ollama(self, mock_config):
        """Test Ollama provider detection"""
        config = mock_config.copy()
        config["anthropic_api_key"] = ""
        config["openai_api_key"] = ""
        config["ollama_endpoint"] = "http://localhost:11434"
        config["ai_provider"] = "auto"

        provider = detect_ai_provider(config)
        assert provider == "ollama"

    def test_manual_provider_selection(self, mock_config):
        """Test manual provider selection"""
        config = mock_config.copy()
        config["ai_provider"] = "anthropic"

        provider = detect_ai_provider(config)
        assert provider == "anthropic"

    def test_no_provider_configured(self):
        """Test when no provider is configured"""
        config = {"ai_provider": "auto", "anthropic_api_key": "", "openai_api_key": "", "ollama_endpoint": ""}

        provider = detect_ai_provider(config)
        assert provider is None

    def test_get_model_name_defaults(self, mock_config):
        """Test default model names for each provider"""
        assert get_model_name("anthropic", {"model": "auto"}) == "claude-sonnet-4-5-20250929"
        assert get_model_name("openai", {"model": "auto"}) == "gpt-4-turbo-preview"
        assert get_model_name("ollama", {"model": "auto"}) == "llama3.2:3b"

    def test_get_model_name_custom(self, mock_config):
        """Test custom model name"""
        config = {"model": "custom-model-name"}
        assert get_model_name("anthropic", config) == "custom-model-name"
