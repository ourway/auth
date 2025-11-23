
import logging
import logging.config

from pythonjsonlogger import json as jsonlogger


class JsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(JsonFormatter, self).add_fields(log_record, record, message_dict)
        if not log_record.get('timestamp'):
            log_record['timestamp'] = record.created
        if log_record.get('level'):
            log_record['level'] = log_record['level'].upper()
        else:
            log_record['level'] = record.levelname

def setup_logging(log_level=logging.INFO):
    logging.config.dictConfig({
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'json': {
                '()': JsonFormatter,
                'format': '%(asctime)s %(name)s %(levelname)s %(message)s'
            },
        },
        'handlers': {
            'json': {
                'class': 'logging.StreamHandler',
                'formatter': 'json'
            },
        },
        'loggers': {
            '': {
                'handlers': ['json'],
                'level': log_level,
            },
        }
    })
