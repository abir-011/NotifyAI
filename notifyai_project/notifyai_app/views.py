from django.shortcuts import render,redirect
import os,json,re
import requests
from django.contrib import messages
import google.auth.transport.requests
from django.conf import settings
from django.http import JsonResponse
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
import googleapiclient.discovery
from googleapiclient.discovery import build
from datetime import datetime,timedelta,timezone
import pytz
from google_auth_oauthlib.flow import Flow
import google.generativeai as genai
from django.conf import settings
from .gemini import get_gemini_response
from dotenv import load_dotenv
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import logout as django_logout
from django.shortcuts import redirect
load_dotenv()

def home(request):
    return render(request, 'home.html')

SCOPES = settings.GOOGLE_OAUTH2_SCOPES

def home(request):
    return render(request, 'home.html', {
        'user_authenticated': 'credentials' in request.session
    })

#Redirect user to Google OAuth
def google_login(request):
    client_secrets_file = settings.GOOGLE_OAUTH2_CLIENT_SECRETS_JSON
    redirect_uri = settings.BASE_URL + "/auth/callback/"

    flow = Flow.from_client_secrets_file(
        client_secrets_file,
        scopes=settings.GOOGLE_OAUTH2_SCOPES,
        redirect_uri=redirect_uri
    )

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    # Save state in session BEFORE redirect
    request.session['state'] = state
    request.session.modified = True  # ensure session is saved immediately
    return redirect(authorization_url)


#@csrf_exempt 
def auth_callback(request):
    # Get the state from session (must exist)
    state = request.session.get("state")
    if not state:
        print("⚠️ No state in session!")
        return redirect('google_login')  # or your login URL name

    client_secrets_file = settings.GOOGLE_OAUTH2_CLIENT_SECRETS_JSON
    redirect_uri = settings.BASE_URL + "/auth/callback/"

    flow = Flow.from_client_secrets_file(
        client_secrets_file,
        scopes=settings.GOOGLE_OAUTH2_SCOPES,
        state=state,
        redirect_uri=redirect_uri
    )

    authorization_response = request.build_absolute_uri()

    # 🔍 Add debug output here
    print("📥 OAuth callback received:")
    print("🔒 Expected state from session:", state)
    print("🔐 Saving state in session:", state)
    print("🌐 Full callback URL:", authorization_response)

    # Fetch token
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials

    request.session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    # Optional: clear state from session after success
    try:
        del request.session['state']
    except KeyError:
        pass

    return redirect('dashboard')

def dashboard(request):
    credentials = request.session.get('credentials')
    if not credentials:
        return redirect('google_login')

    return render(request, 'dashboard.html', {
        'user': request.session.get('user_info', {})  # optionally pass user data
    })

def credentials_to_dict(credentials):
    """Converts credentials to a dictionary for storage"""
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }


def create_google_calendar_event(access_token, event_details):
    creds = Credentials.from_authorized_user_info(info={"access_token": access_token})

    service = build("calendar", "v3", credentials=creds)
    
    event = {
        "summary": event_details["summary"],
        "description": event_details["description"],
        "start": {
            "dateTime": event_details["start_time"],
            "timeZone": 'UTC',
        },
        "end": {
            "dateTime": event_details["end_time"],
            "timeZone": 'UTC',
        },
        "reminders": {
            "useDefault": False,
            "overrides": [
                {"method": "popup", "minutes": 10},
            ],
        },
    }

    event = service.events().insert(calendarId="primary", body=event).execute()
    return event


def create_google_task(access_token, task_details):
    creds = Credentials.from_authorized_user_info(info={"access_token": access_token})

    service = build("tasks", "v1", credentials=creds)

    task = {
        "title": task_details["title"],
        "notes": task_details["notes"],
        "due": task_details["due_time"],
    }

    task = service.tasks().insert(tasklist="@default", body=task).execute()
    return task


import re

def parse_prompt(prompt):
    # This is a very basic implementation for detecting tasks vs events
    event_keywords = ["remind", "event", "meeting", "appointment"]
    
    if any(keyword in prompt.lower() for keyword in event_keywords):
        # Extract date and time from the prompt (e.g., "at 6pm today")
        time_match = re.search(r"(\d{1,2}:\d{2}\s?(am|pm))", prompt)
        if time_match:
            start_time = time_match.group(1)
            # Create event details
            return {
                "type": "event",
                "summary": prompt,
                "start_time": f"2025-04-26T{start_time}:00",  # Just an example start time
                "end_time": f"2025-04-26T{start_time}:00",  # Same as start time for simplicity
                "description": "Created from prompt"
            }

    # Default: Create Task
    return {
        "type": "task",
        "title": prompt,
        "notes": "Task created from prompt",
        "due_time": "2025-04-26T12:00:00Z"  # Example due date
    }

def get_gemini_response(prompt):
    model = genai.GenerativeModel("gemini-2.0-flash")

    system_prompt = """
You are an assistant that helps convert natural language into structured data. For every input, extract:
- action_type: either "event" or "task"
- title: short title of the event/task
- datetime: in ISO format (e.g. 2025-06-01T17:00:00)

Respond only in valid JSON like:
{
  "action_type": "event",
  "title": "Call John",
  "datetime": "2025-06-01T17:00:00"
}
"""

    response = model.generate_content([system_prompt, prompt])
    raw_text = response.text.strip()
    print("Raw Gemini response:", repr(raw_text))

    # Strip markdown code blocks ```json ... ```
    cleaned_text = re.sub(r"^```json\s*|\s*```$", "", raw_text, flags=re.DOTALL).strip()

    try:
        data = json.loads(cleaned_text)
        return data
    except Exception as e:
        print("Gemini parsing error:", e)
        return {}
    

def is_only_time(s):
    return bool(re.fullmatch(r"\d{2}:\d{2}(:\d{2})?", s))

def process_prompt(request):
    if request.method == 'POST':
        prompt = request.POST.get('prompt')
        if not prompt:
            messages.error(request, "Prompt cannot be empty.")
            return redirect('home')

        creds_dict = request.session.get('credentials')
        if not creds_dict:
            return redirect('login')

        credentials = google.oauth2.credentials.Credentials(**creds_dict)

        result = get_gemini_response(prompt)
        action_type = result.get("action_type")
        title = result.get("title")
        datetime_str = result.get("datetime")  # Can be full datetime, time only, or None

        if not action_type or not title:
            messages.error(request, "Could not understand your input.")
            return redirect('home')

        now_utc = datetime.now(timezone.utc)
        event_dt = None

        if datetime_str:
            try:
                gemini_dt = datetime.fromisoformat(datetime_str)

                now = datetime.now(timezone.utc)

                # Sanitize unreasonable years (before now or way into the future)
                if gemini_dt.year < now.year or gemini_dt.year > now.year + 1:
                    # Just use today's date + Gemini's time
                    event_dt = now.replace(
                        hour=gemini_dt.hour,
                        minute=gemini_dt.minute,
                        second=gemini_dt.second if gemini_dt.second else 0,
                        microsecond=0
                    )

                    # If that time already passed today, schedule for tomorrow
                    if event_dt < now:
                        event_dt += timedelta(days=1)
                else:
                    # Use Gemini's datetime directly
                    event_dt = gemini_dt.astimezone(timezone.utc)

            except Exception as e:
                messages.error(request, f"Invalid date format: {e}")
                return redirect('home')

        # Handle Events
        if action_type == "event":
            if not event_dt:
                messages.error(request, "Event must include valid date/time.")
                return redirect('home')

            service = googleapiclient.discovery.build("calendar", "v3", credentials=credentials)
            event = {
                'summary': title,
                'start': {'dateTime': event_dt.isoformat(), 'timeZone': 'UTC'},
                'end': {'dateTime': (event_dt + timedelta(hours=1)).isoformat(), 'timeZone': 'UTC'}
            }
            service.events().insert(calendarId='primary', body=event).execute()

            # Format datetime nicely for message, e.g. April 30, 2025, 06:00 PM UTC
            formatted_dt = event_dt.strftime('%B %d, %Y, %I:%M %p %Z')+ ' UTC'
            messages.success(request, f"Calendar event '{title}' created successfully for {formatted_dt}!")

        # Handle Tasks
        elif action_type == "task":
            service = googleapiclient.discovery.build("tasks", "v1", credentials=credentials)
            task = {'title': title}
            if event_dt:
                # Set due date (date only)
                task['due'] = event_dt.date().isoformat() + 'T00:00:00.000Z'
                # Add time info in notes
                formatted_time = event_dt.strftime('%I:%M %p %Z') or event_dt.strftime('%I:%M %p')  # fallback if %Z empty
                task['notes'] = f"Due time: {formatted_time}"
            service.tasks().insert(tasklist='@default', body=task).execute()
            messages.success(request, "Task created successfully!")

            if event_dt:
                formatted_due = event_dt.strftime('%B %d, %Y')
                messages.success(request, f"Task '{title}' created successfully with due date {formatted_due}!")
            else:
                messages.success(request, f"Task '{title}' created successfully!")

        else:
            messages.error(request, "Unsupported action type.")
            return redirect('home')

        # Refresh credentials
        request.session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }

        print("Prompt:", prompt)
        print("Gemini result:", result)
        print("Datetime (raw):", datetime_str)
        print("Datetime (parsed):", event_dt)
        print("Title:", title)
        response_data = {
            'response': f"✅ {action_type.capitalize()} '{title}' created successfully!",
            'prompt': prompt
        }

        return render(request, 'dashboard.html', response_data)
    
def logout_view(request):
    logout(request)
    # Clear session data
    django_logout(request)  # clears auth
    request.session.flush()  # clears all session data
    return redirect('google_login')



genai.configure(api_key=settings.GEMINI_API_KEY)

