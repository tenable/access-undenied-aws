from __future__ import annotations

import collections.abc
import re
from typing import Union, Tuple


def get_iterable(x: collections.Iterable) -> Union[object, Tuple[object]]:
    if x is None:
        return ()
    if isinstance(x, collections.abc.Iterable):
        return x
    else:
        return (x,)


def get_regex_match_group_or_none(match: re.Match, group_name: str):
    if not match:
        return None
    try:
        return match.group(group_name)
    except IndexError:
        return None
