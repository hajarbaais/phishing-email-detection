import logging 
import sys

def setup_logger( ):

    logger=logging.getLogger('PhishingDetector')
    logger.setLevel(logging.DEBUG)
    logger.propagate=False
    handler=logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    if not logger.handlers:
        logger.addHandler(handler)
    return logger

logger=setup_logger()
