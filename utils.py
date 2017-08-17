"""
Utils for pktgen.
"""


def csv2list(csv):
    """ Converts a CSV string into a list. """
    return [i.strip() for i in csv.split(',')]
