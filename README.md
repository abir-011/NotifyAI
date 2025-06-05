# NotifyAI

**NotifyAI** is an AI-powered task and calendar assistant web application that helps users create events and reminders via natural language prompts. It integrates Google OAuth for login, Google Calendar and Google Tasks for event and task management, and uses Gemini AI to parse natural language into structured actions.
<br><br> The app is now live at [notifyai-n9dx.onrender.com](https://notifyai-n9dx.onrender.com/)

---

## Features

- **Google OAuth Login:** Secure user authentication with Google accounts.
- **Natural Language Input:** Users can type prompts like "Remind me to call John tomorrow at 5pm" and NotifyAI will parse and create appropriate calendar events or tasks.
- **Google Calendar & Tasks Integration:** Automatically adds events and reminders to your Google Calendar and Tasks.
- **Dark Mode Support:** User interface supports light and dark themes with persistence.
- **Responsive UI:** Built with TailwindCSS for clean, responsive design.
- **Session Management:** Safe handling of user sessions and OAuth tokens.
- **Prompt Processing:** Backend processes natural language prompts through Gemini AI for accurate scheduling.

---

## Tech Stack

- **Backend:** Django (Python)
- **Frontend:** Django Templates with TailwindCSS
- **Authentication:** Google OAuth 2.0
- **AI Parsing:** Gemini AI (Generative AI API)
- **Deployment:** Render (or your chosen cloud provider)

---

## Getting Started

### Prerequisites

- Python 3.8+
- Google Cloud project with OAuth credentials
- Gemini AI API access (or your configured AI service)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/NotifyAI.git
cd NotifyAI
```

2. Install Dependencies:

```bash
pip install -r requirements.txt
```

3. Configure Google OAuth:

- Place your Google client secret JSON in notifyai_project/client_secret.json

- Update settings.py with your Google OAuth client ID and secret, or environment variables.



4. Run migrations:
```bash
python manage.py migrate
```

5. Run the development server:
```bash
python manage.py runserver
```
6. Open http://localhost:8000 in your browser.


## Usage
-Click Login with Google to sign in.

-Enter your task or event prompt in natural language.

-Submit the form to create calendar events or reminders.

-Use the dark mode toggle at the top-right to switch themes.


## Acknowledgments
- Google OAuth 2.0

- TailwindCSS

- Gemini AI (or your AI service)

- Thanks to the open source community for inspiration and tools.
