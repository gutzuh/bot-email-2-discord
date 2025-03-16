from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import base64
import binascii
import requests
import os
import re
import json
from bs4 import BeautifulSoup

ESCOPOS = ['https://www.googleapis.com/auth/gmail.readonly']

def base64decode(data):
    if not data:
        return b""
    return base64.urlsafe_b64decode(data)

def get_email_body(msg, serv):
    body = ""
    images = []

    if msg['payload']['mimeType'] == 'text/plain':
        if 'body' in msg['payload'] and 'data' in msg['payload']['body']:
            try:
                body = base64decode(msg['payload']['body']['data']).decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                print("Erro ao decodificar corpo do e-mail em texto puro")
    elif msg['payload']['mimeType'] == 'text/html':
        if 'body' in msg['payload'] and 'data' in msg['payload']['body']:
            try:
                body = base64decode(msg['payload']['body']['data']).decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                print("Erro ao decodificar corpo do e-mail em HTML")

    if 'parts' in msg['payload']:
        for part in msg['payload']['parts']:
            if part['mimeType'] == 'text/plain':
                if 'body' in part and 'data' in part['body'] and part['body'].get('size', 0) != 0:
                    try:
                        body = base64decode(part['body']['data']).decode('utf-8')
                    except (binascii.Error, UnicodeDecodeError):
                        print("Erro ao decodificar parte do e-mail em texto puro")
            elif part['mimeType'] == 'text/html':
                if 'body' in part and 'data' in part['body']:
                    try:
                        body = base64decode(part['body']['data']).decode('utf-8')
                    except (binascii.Error, UnicodeDecodeError):
                        print("Erro ao decodificar parte do e-mail em HTML")
            elif part['mimeType'].startswith('image/'):
                if 'body' in part and 'attachmentId' in part['body']:
                    attachment_id = part['body']['attachmentId']
                    attachment_response = serv.users().messages().attachments().get(
                        userId='me', messageId=msg['id'], id=attachment_id
                    ).execute()
                    image_data = attachment_response.get('data')
                    image_name = part.get('filename', 'imagem.png')
                    images.append((image_name, image_data))
                else:
                    print("No images")
    return body, images

def limpar_string(description):
    description = description.replace('\r\n', ' ').replace('\xc2\xa0', ' ')
    description = description.decode('utf-8') if isinstance(description, bytes) else description
    description = re.sub(r'!?$https?:\/\/[^\s]+?$', '', description)
    description = BeautifulSoup(description, 'html.parser').get_text()
    description = re.sub(r'\s+', ' ', description)
    return description.strip()

def format_webhook_message(text):
    formatted_text = re.sub(r'([.!?])\s+(?=[A-Z])', r'\1\n', text)
    emoji_pattern = (
        "[" 
        "\U0001F300-\U0001F5FF"
        "\U0001F600-\U0001F64F"
        "\U0001F680-\U0001F6FF"
        "\U0001F700-\U0001F77F"
        "\U0001F780-\U0001F7FF"
        "\U0001F800-\U0001F8FF"
        "\U0001F900-\U0001F9FF"
        "\U0001FA00-\U0001FA6F"
        "\U0001FA70-\U0001FAFF"
        "]+"
    )
    formatted_text = re.sub(r'(?<!\n)(' + emoji_pattern + ')', r'\n\1', formatted_text)
    formatted_text = re.sub(r'\n+', '\n', formatted_text)
    return formatted_text.strip()

def send_webhook(body, imgs, serv, msg_id, msg):
    if not body:
        body = "Email sem Corpo"
    formatted_body = format_webhook_message(body)
    
    url = "https://discordapp.com/api/webhooks/############/##################################" # inserir webhook
    
    embed = {
        "title": f"{msg.get('snippet', '')}...",
        "description": formatted_body,
        "color": 5814783
    }
    
    files = None
    if imgs:
        files = {}
        for i, (image_name, image_data) in enumerate(imgs):
            try:
                file_data = base64.urlsafe_b64decode(image_data)
            except Exception as e:
                print(f"Erro decodificando imagem {image_name}: {e}")
                continue
            files[f'file{i}'] = (image_name, file_data)
        embed["image"] = {"url": f"attachment://{imgs[0][0]}"}
    
    payload = {"embeds": [embed]}
    
    try:
        if files:
            data = {"payload_json": json.dumps(payload)}
            res = requests.post(url, data=data, files=files)
        else:
            res = requests.post(url, json=payload)
        if res.status_code in (200, 204):
            print('Dados enviados para o webhook com sucesso!')
            serv.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
        else:
            print(f'Falha ao enviar dados para o webhook: {res.status_code} - {res.text}')
    except Exception as e:
        print(f"Exceção ao enviar webhook: {e}")

def main():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file('token.json', ESCOPOS)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', ESCOPOS)
            creds = flow.run_local_server(port=8080)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    
    serv = build('gmail', 'v1', credentials=creds)
    res = serv.users().messages().list(
        userId="me", 
        labelIds=['INBOX'], 
        q='-{classroom.google.com OR google.com} is:unread'
    ).execute()
    msgs = res.get('messages', [])
    if not msgs:
        print("Sem Atualizacoes")
    else:
        for m in msgs:
            msg = serv.users().messages().get(userId="me", id=m['id']).execute()
            msg_id = m['id']
            body, images = get_email_body(msg, serv)
            body = limpar_string(body)
            send_webhook(body, images, serv, msg_id, msg)

if __name__ == '__main__':
    main()
