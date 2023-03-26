from multiprocessing import cpu_count



# Worker Options

workers = cpu_count() + 1
bind = "0.0.0.0:8080"
worker_class = 'uvicorn.workers.UvicornWorker'

# Logging Options

loglevel = 'debug'