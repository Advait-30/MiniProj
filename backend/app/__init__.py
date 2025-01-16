from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from datetime import timedelta

def create_app():
    app = Flask(__name__)
    
    # Configure app
    app.config.update(
        SECRET_KEY='dev-secret-key',  # Change in production
        JWT_SECRET_KEY='jwt-secret-key',  # Change in production
        JWT_ACCESS_TOKEN_EXPIRES=timedelta(hours=1),
        CORS_HEADERS='Content-Type'
    )
    
    # Initialize extensions
    CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})
    jwt = JWTManager(app)
    
    # Register blueprints
    from .routes.auth import auth_bp
    from .routes.wban import wban_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(wban_bp, url_prefix='/api/wban')
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        return {'status': 'healthy'}, 200
        
    return app 