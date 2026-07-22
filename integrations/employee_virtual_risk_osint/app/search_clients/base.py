from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from app.models import SearchResult


class SearchClientError(RuntimeError):
    pass


class SearchClient(ABC):
    name = "base"

    @abstractmethod
    def search(self, query: str, count: int = 10) -> List[SearchResult]:
        raise NotImplementedError
