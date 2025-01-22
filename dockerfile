# Use Python Alpine base image
FROM python:3.13.0-alpine3.20

# Set working directory
WORKDIR /home/app

# Copy necessary files
COPY main.py .
COPY requirements.txt .

# Install dependencies
RUN pip install -r requirements.txt

# Set entrypoint
ENTRYPOINT ["python", "/home/app/main.py"]