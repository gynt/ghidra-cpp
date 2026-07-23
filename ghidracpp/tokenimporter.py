import pathlib
from dataclasses import field, dataclass
from dataclasses_json import dataclass_json, config
from typing import List, Optional

@dataclass_json
@dataclass
class Token:
  cls: str
  token: str
  def __repr__(self) -> str:
    return self.token

@dataclass_json
@dataclass
class TokenGroup:
  cls: str
  nodes: List["TokenGroup | Token"] = field(metadata=config(decoder=lambda X: dec(X)))
  def __repr__(self) -> str:
    return "".join(str(node) for node in self.nodes)
  def __iter__(self):
    return iter(self.nodes)
  def __getitem__(self, key):
    return self.nodes[key]

def dec(l):
  return [Token.from_dict(x) if "token" in x else TokenGroup.from_dict(x) for x in l]

import os

def import_token_export(data: str | None = None):
  if not data:
    data = (pathlib.Path(__file__).parent / "testdata-01.json").read_text()
  markup = TokenGroup.from_json(data)
  return markup