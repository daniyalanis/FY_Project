# 1. Start from an official SageMath image
FROM sagemath/sagemath:10.3

# 2. Set the working directory inside the container
WORKDIR /app

# 3. Install Python dependencies used by tool web apps
COPY Tools/ECA_Tools/WebApp/requirements.txt ./requirements.txt
RUN sage -pip install --no-cache-dir -r requirements.txt

# 4. Copy the homepage gateway and tool sources
COPY . .

# 5. Run the gateway app on port 8000 (Render honors $PORT)
ENTRYPOINT []
ENV PORT=8000
EXPOSE 8000
CMD ["sh", "-c", "sage -python -m gunicorn --bind 0.0.0.0:${PORT:-8000} --workers 1 --threads 8 --timeout 120 app:application"]
