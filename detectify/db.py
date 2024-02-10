from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Integer, Float


Base = declarative_base()


class AnalysisInfo(Base):
    __tablename__ = "analysis_info"

    id = Column(Integer, autoincrement=True, primary_key=True)
    sha256 = Column(String, unique=True)
    report_path = Column(String)
    file_path = Column(String)
    score = Column(Float)
    label = Column(String)
