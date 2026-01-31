#!/usr/bin/env python3
"""
Checkmate Vulnerability Scanner - Application Launcher
Handles proper initialization and keeps the app running
"""

if __name__ == '__main__':
    try:
        from app import app
        print(" ")
        print("=" * 70)
        print("CHECKMATE VULNERABILITY SCANNER")
        print("=" * 70)
        print()
        print("Launching Flask development server...")
        print("Access the application at: http://localhost:5000")
        print("OR at: http://127.0.0.1:5000")
        print()
        print("Press CTRL+C to stop the server")
        print("=" * 70)
        print()
        
        # Run the Flask application
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=False,
            use_reloader=False,
            threaded=True
        )
        
    except Exception as e:
        print(f"[ERROR] Failed to start application: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
