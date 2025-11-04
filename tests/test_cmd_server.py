from unittest.mock import patch

from auth.cmd.server import main


@patch("auth.cmd.server.serve")
@patch("auth.cmd.server.print")
def test_main_function(mock_print, mock_serve):
    """Test the main function in cmd.server module"""
    # Test with default port
    main()

    # Check that print was called to display the help message
    assert mock_print.call_count >= 2  # At least the welcome message and help

    # Check that serve was called with the default port
    mock_serve.assert_called_once_with(port=4000)


@patch("auth.cmd.server.serve")
@patch("auth.cmd.server.print")
def test_main_function_custom_port(mock_print, mock_serve):
    """Test the main function with a custom port"""
    # Test with custom port
    main(port=5000)

    # Check that serve was called with the custom port
    mock_serve.assert_called_with(port=5000)
