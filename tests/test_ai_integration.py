import pytest
import sys
import os
from unittest.mock import patch, MagicMock

# Add the parent directory to the Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_modules.ai_integration import get_ai_advice, predict_threats

@patch('ollama.Client')
def test_get_ai_advice(mock_client_class):
    # Setup mock client instance and response
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    mock_client.chat.return_value = {
        'message': {
            'content': 'Test AI advice response'
        }
    }
    
    # Test getting AI advice
    test_data = {'test': 'data'}
    result = get_ai_advice(test_data)
    assert result == 'Test AI advice response'
    
    # Verify client was created and chat was called
    mock_client_class.assert_called()
    mock_client.chat.assert_called()
    
    # Verify prompt contains data
    call_args = mock_client.chat.call_args[1]
    assert 'messages' in call_args
    assert 'test' in str(call_args['messages'][0]['content'])

@patch('ollama.Client')
def test_get_ai_advice_error(mock_client_class):
    # Setup mock client to raise exception on first call, succeed on second
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    mock_client.chat.side_effect = [Exception("Test error"), {
        'message': {
            'content': 'Fallback response'
        }
    }]
    
    # Test error handling with fallback
    test_data = {'test': 'data'}
    result = get_ai_advice(test_data)
    assert result == 'Fallback response'
    
    # Should be called twice (first fails, second succeeds)
    assert mock_client_class.call_count == 2

@patch('ollama.Client')
def test_get_ai_advice_complete_failure(mock_client_class):
    # Setup mock client to always fail
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    mock_client.chat.side_effect = Exception("Test error")
    
    # Test complete failure
    test_data = {'test': 'data'}
    result = get_ai_advice(test_data)
    assert "Failed to connect to Ollama" in result

@patch('ollama.Client')
def test_predict_threats(mock_client_class):
    # Setup mock client instance and response
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    mock_client.chat.return_value = {
        'message': {
            'content': 'Test threat prediction'
        }
    }
    
    # Test threat prediction
    test_logs = ['test log 1', 'test log 2']
    result = predict_threats(test_logs)
    assert result == 'Test threat prediction'
    
    # Verify client was created and chat was called
    mock_client_class.assert_called()
    mock_client.chat.assert_called()
    
    # Verify prompt contains logs
    call_args = mock_client.chat.call_args[1]
    assert 'messages' in call_args
    assert 'test log 1' in str(call_args['messages'][0]['content'])
    assert 'test log 2' in str(call_args['messages'][0]['content'])

@patch('ollama.Client')
def test_predict_threats_empty_logs(mock_client_class):
    # Setup mock client instance and response
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    mock_client.chat.return_value = {
        'message': {
            'content': 'Empty logs response'
        }
    }
    
    # Test with empty logs
    result = predict_threats([])
    assert result == 'Empty logs response'
    
    # Verify client was created and chat was called
    mock_client_class.assert_called()
    mock_client.chat.assert_called()
    
    # Verify prompt handles empty logs appropriately
    call_args = mock_client.chat.call_args[1]
    assert 'messages' in call_args

@patch('ollama.Client')
def test_predict_threats_error(mock_client_class):
    # Setup mock client to always fail
    mock_client = MagicMock()
    mock_client_class.return_value = mock_client
    mock_client.chat.side_effect = Exception("Test error")

    # Test error handling
    test_logs = ['test log']
    result = predict_threats(test_logs)

    # Should return error message on complete failure
    assert "AI prediction service temporarily unavailable" in result
