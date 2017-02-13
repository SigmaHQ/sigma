# Sigma parser

import yaml
import re

class SigmaParser:
    def __init__(self, sigma):
        self.parsedyaml = yaml.safe_load(sigma)

