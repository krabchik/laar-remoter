# Use an official Python image as a base
FROM python:3.11-slim

RUN apt-get update
RUN apt-get install iputils-ping -y
RUN apt-get install net-tools

# Set the working directory to /app
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install the dependencies
RUN pip install -r requirements.txt

# Copy the application code
COPY remoter remoter
COPY data.py data.py
COPY execute.py execute.py

# For debug
COPY data.yaml data.yaml

EXPOSE 5000

# Run the command to start the application when the container launches
CMD ["flask", "--app", "remoter:app", "run", "--host=0.0.0.0"]