import logging
from logging import StreamHandler


class LogStreamHandler(StreamHandler):
    def __init__(self):
        StreamHandler.__init__(self)
        self.logs = []

    def emit(self, record: logging.LogRecord):
        self.format(record)
        print("hi")
        print(record)
        self.logs.append({"level": record.levelname, "message": record.msg, "time": record.created})

    def encode(self):
        # encode in reverse chronological order
        return list(reversed(self.logs))
