from unittest.mock import patch

from auth.server import main


@patch("auth.server.CPUs", 2)  # Mock CPU count to be 2 for predictable testing
@patch("auth.server.serve")
@patch("auth.server.print")
def test_main_function_default(mock_print, mock_serve):
    """Test the main function in server module with default parameters"""
    # Test with default parameters
    main()

    # Check that print was called to display the welcome message and help
    assert mock_print.call_count >= 2  # At least the welcome message and help

    # Check that waitress.serve was called with the correct parameters
    # The actual app instance is passed, not the string
    assert mock_serve.call_count == 1
    call_args = mock_serve.call_args
    assert (
        call_args[0][0].__class__.__name__ == "Flask"
    )  # First arg should be Flask app
    assert call_args[1]["host"] == "0.0.0.0"
    assert call_args[1]["port"] == 4000
    assert call_args[1]["threads"] == 4  # min(CPUs * 2, 4) = min(4, 4) = 4


@patch("auth.server.CPUs", 2)  # Mock CPU count to be 2 for predictable testing
@patch("auth.server.serve")
@patch("auth.server.print")
def test_main_function_custom_params(mock_print, mock_serve):
    """Test the main function with custom parameters"""
    # Test with custom host and port
    main(port=5000, host="127.0.0.1")

    # Check that waitress.serve was called with the custom parameters
    assert mock_serve.call_count == 1
    call_args = mock_serve.call_args
    assert (
        call_args[0][0].__class__.__name__ == "Flask"
    )  # First arg should be Flask app
    assert call_args[1]["host"] == "127.0.0.1"
    assert call_args[1]["port"] == 5000
    assert call_args[1]["threads"] == 4  # min(CPUs * 2, 4) = min(4, 4) = 4


@patch("auth.server.CPUs", 8)  # Mock CPUs to be 8 to test thread count limiting
@patch("auth.server.serve")
@patch("auth.server.print")
def test_main_function_max_workers(mock_print, mock_serve):
    """Test the main function respects maximum thread count"""
    # CPUs is 8, so threads should be min(8*2, 4) = 4
    main()

    # Capture the actual call to verify thread count
    call_args = mock_serve.call_args
    assert (
        call_args[1]["threads"] == 4
    )  # Should be limited to 4 even with high CPU count
