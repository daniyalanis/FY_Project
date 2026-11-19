# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set DEBIAN_FRONTEND to noninteractive to avoid prompts during apt-get install
ENV DEBIAN_FRONTEND=noninteractive

# Install sagemath and other system dependencies
# These installations are done as root
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    sagemath \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Define arguments for user and group IDs and username
ARG USER_ID=1000
ARG GROUP_ID=1000
ARG APP_USER=appuser

# Create a non-root user and group, and its home directory.
# Set HOME environment variable.
ENV APP_USER=${APP_USER}
ENV HOME=/home/${APP_USER}

RUN groupadd -g ${GROUP_ID} ${APP_USER} && \
    useradd -u ${USER_ID} -g ${APP_USER} -ms /bin/bash -d ${HOME} ${APP_USER} && \
    mkdir -p ${HOME}/.sage ${HOME}/.streamlit ${HOME}/.cache ${HOME}/.config ${HOME}/.local && \
    chown -R ${APP_USER}:${APP_USER} ${HOME}

# Set the working directory in the container
# This directory will be created by WORKDIR if it doesn't exist and owned by root initially.
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt ./

# Install any needed packages specified in requirements.txt
# This is still done as root, before we copy app code or switch user.
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the src directory (containing your Python app and scripts) into the container at /app/src
COPY src/ ./src/

# Change ownership of the /app directory and its contents to the non-root user
# This ensures the application runs with appropriate permissions for its own files if needed.
RUN chown -R ${APP_USER}:${APP_USER} /app

# Switch to the non-root user. Subsequent commands run as this user.
USER ${APP_USER}

# Make port 8501 available to the world outside this container (Streamlit's default port)
EXPOSE 8501

# Healthcheck for Streamlit (runs as APP_USER)
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health

# Run streamlit_app.py when the container launches
# This will be executed as APP_USER, and HOME is set to /home/appuser.
# SageMath and Streamlit should now create their .sage and .streamlit directories
# in /home/appuser/.sage and /home/appuser/.streamlit respectively.
ENTRYPOINT ["streamlit", "run", "src/streamlit_app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.enableXsrfProtection=false", "--server.maxUploadSize=50"]