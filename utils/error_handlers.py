from flask import render_template, jsonify, request, current_app
from flask_login import current_user
from werkzeug.exceptions import HTTPException
import logging

def init_error_handlers(app):
    """Initialize error handlers for the application."""

    @app.errorhandler(Exception)
    def handle_exception(e):
        """Handle all unhandled exceptions."""
        logging.error(f"Unhandled exception: {str(e)}", exc_info=True)

        if isinstance(e, HTTPException):
            return render_template('error.html', error=e), e.code

        return render_template('error.html',
                             error={'code': 500, 'description': 'Internal Server Error'}), 500

    @app.errorhandler(404)
    def not_found_error(e):
        """Handle 404 errors."""
        logging.warning(f"404 error: {request.url}")
        return render_template('error.html', error=e), 404

    @app.errorhandler(403)
    def forbidden_error(e):
        """Handle 403 errors."""
        logging.warning(f"403 error for user {current_user.get_id()}: {request.url}")
        return render_template('error.html', error=e), 403

def handle_error(error):
    """Handle errors in a consistent way."""
    logging.error(f"Error handled: {str(error)}")
    return {
        'status': 'error',
        'message': str(error)
    }
