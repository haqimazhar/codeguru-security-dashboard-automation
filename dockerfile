FROM python:3.13.0-alpine3.20

COPY main.py /home/app/main.py
COPY requirements.txt /home/app/requirements.txt

# Install dependencies
RUN pip install -r requirements.txt

# Action entrypoint
ENTRYPOINT ["python", "/home/app/main.py"]