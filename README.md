# Automated Incident Response System

This project is an Automated Incident Response System designed to detect and mitigate security threats in a web application environment. It uses machine learning models to analyze network traffic and user behavior to identify potential incidents and automate the response process.

## Features

*   **Zero-Trust Packet Analysis:** Analyzes network packets using machine learning models to identify malicious traffic.
*   **Honeypot:** A honeypot website to lure and identify attackers.
*   **Automated Mitigation:** Automatically takes action to mitigate identified threats, such as dropping packets.
*   **Web-based Dashboard:** A Flask-based web interface for monitoring and managing the system.
*   **User Authentication:** Secure user authentication for accessing the dashboard.

## Project Structure

The project is organized into the following directories:

*   `Models/`: Contains the machine learning models used for packet analysis.
*   `honeypot_website/`: A separate Flask application that acts as a honeypot.
*   `services/`: Contains the core logic for data processing, database interaction, mitigation, and other services.
*   `static/`: Static assets for the main web application (CSS, JavaScript, images).
*   `templates/`: HTML templates for the main web application.
*   `tests/`: Unit tests for the application's services.

## Getting Started

### Prerequisites

*   Python 3.x
*   pip

### Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/Aakriti-2334/AutomatedIncidentResponseSystem.git
    ```
2.  Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  To start the main application:
    ```bash
    python app.py
    ```
2.  To start the honeypot application:
    ```bash
    python honeypot_website/honeypot_app.py
    ```

## Testing

To run the tests, use `pytest`:
```bash
pytest
```
