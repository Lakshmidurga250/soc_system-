"""Generic Base Repository with SQLAlchemy 2.0 type support."""
from typing import Generic, TypeVar, Type, Any, Sequence
from sqlalchemy import select, func, desc
from sqlalchemy.orm import Session

ModelType = TypeVar("ModelType", bound=Any)

class BaseRepository(Generic[ModelType]):
    def __init__(self, model: Type[ModelType], db: Session):
        self.model = model
        self.db = db

    def get(self, id: str) -> ModelType | None:
        return self.db.get(self.model, id)

    def list(self, skip: int = 0, limit: int = 100) -> Sequence[ModelType]:
        stmt = select(self.model).offset(skip).limit(limit)
        return self.db.scalars(stmt).all()

    def count(self) -> int:
        stmt = select(func.count()).select_from(self.model)
        return self.db.scalar(stmt) or 0

    def create(self, obj: ModelType) -> ModelType:
        self.db.add(obj)
        self.db.flush()
        return obj

    def update(self, obj: ModelType) -> ModelType:
        self.db.add(obj)
        self.db.flush()
        return obj

    def delete(self, obj: ModelType) -> None:
        self.db.delete(obj)
        self.db.flush()
