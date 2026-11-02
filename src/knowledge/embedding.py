"""small 编码器：区分问题前缀与正文，按 tokenizer 分块，输出归一化的 512 维向量。"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Protocol

from .config import MODEL_ID, VECTOR_SIZE

QUERY_PREFIX = "为这个句子生成表示以用于检索相关文章："


class Encoder(Protocol):
    """编码与分块的最小契约；测试可注入替身，不把测试向量冒充模型输出。"""

    profile: str

    def split(self, text: str) -> list[str]: ...

    def count_tokens(self, text: str) -> int: ...

    def encode_documents(self, texts: Sequence[str]) -> list[list[float]]: ...

    def encode_query(self, text: str) -> list[float]: ...


def check_vectors(vectors: Sequence[Sequence[float]], count: int) -> list[list[float]]:
    """在写库前拦截空向量、维数不符与 NaN，防止污染正式向量空间。"""
    if len(vectors) != count:
        raise ValueError("编码结果数量与输入不一致")
    result = []
    for vector in vectors:
        row = [float(value) for value in vector]
        if len(row) != VECTOR_SIZE or not all(math.isfinite(value) for value in row):
            raise ValueError("small 必须输出有限的 512 维向量")
        norm = math.sqrt(sum(value * value for value in row))
        if norm == 0:
            raise ValueError("编码器返回了零向量")
        result.append([value / norm for value in row])
    return result


class BGEEncoder:
    """固定使用 small；model_path 可指定已下载目录，默认禁止隐式下载权重。"""

    def __init__(self, model_path: str = MODEL_ID, *, model: Any = None) -> None:
        if model is None:
            from sentence_transformers import SentenceTransformer

            try:
                model = SentenceTransformer(
                    model_path, device="cpu", local_files_only=True, trust_remote_code=False
                )
            except OSError as exc:
                raise RuntimeError(
                    "未找到本地 small 权重，请按 src/knowledge/README.md 下载"
                ) from exc
        self.model = model
        if model.get_sentence_embedding_dimension() != VECTOR_SIZE:
            raise ValueError("当前方案只接受 512 维 bge-small-zh-v1.5")
        config = model[0].auto_model.config
        if (
            getattr(config, "hidden_size", None) != VECTOR_SIZE
            or getattr(config, "num_hidden_layers", None) != 4
        ):
            raise ValueError("模型结构与 bge-small-zh-v1.5 不一致")
        # revision 写入索引配置标识；更换模型文件后旧索引不会混入检索。
        revision = getattr(config, "_commit_hash", None)
        if revision is None:
            # 本地目录也必须绑定权重与 tokenizer；不同目录内容不能共用一个模糊的 local 标记。
            digest = hashlib.sha256()
            directory = Path(model_path)
            files = sorted(
                path
                for path in directory.rglob("*")
                if path.is_file() and path.suffix in {".json", ".txt", ".safetensors", ".bin"}
            )
            if not files:
                raise ValueError("本地模型目录缺少可识别的模型文件")
            for path in files:
                digest.update(path.relative_to(directory).as_posix().encode("utf-8"))
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
            revision = digest.hexdigest()[:20]
        self.profile = f"bge-small-zh-v1.5:{revision}:chunk-v1:lex-v1"
        self.max_tokens = min(int(model.max_seq_length), 512)

    def split(self, text: str) -> list[str]:
        """按实际 tokenizer 限长；片段只用于召回，返回时恢复所属完整规则。"""
        if not text.strip():
            raise ValueError("编码文本不能为空")
        tokenizer = self.model.tokenizer
        token_ids = tokenizer.encode(text, add_special_tokens=False)
        capacity = self.max_tokens - tokenizer.num_special_tokens_to_add(pair=False)
        if capacity < 32:
            raise ValueError("模型输入长度过小")
        chunks = []
        for start in range(0, len(token_ids), capacity - 24):
            part = token_ids[start : start + capacity]
            chunks.append(tokenizer.decode(part, skip_special_tokens=True))
            if start + capacity >= len(token_ids):
                break
        return chunks

    def encode_documents(self, texts: Sequence[str]) -> list[list[float]]:
        """正文不添加问题前缀；超长输入必须先拆分，避免模型静默截断。"""
        if not texts:
            return []
        for text in texts:
            self._check_length(text)
        vectors = self.model.encode(
            list(texts), batch_size=16, normalize_embeddings=True, show_progress_bar=False
        )
        return check_vectors(vectors, len(texts))

    def encode_query(self, text: str) -> list[float]:
        query = QUERY_PREFIX + text
        self._check_length(query)
        vectors = self.model.encode([query], normalize_embeddings=True, show_progress_bar=False)
        return check_vectors(vectors, 1)[0]

    def count_tokens(self, text: str) -> int:
        """分块元数据使用真实 tokenizer 计数，避免把字符数当成 token 数。"""
        return len(self.model.tokenizer.encode(text))

    def _check_length(self, text: str) -> None:
        if not text.strip():
            raise ValueError("编码文本不能为空")
        if len(self.model.tokenizer.encode(text)) > self.max_tokens:
            raise ValueError("文本超过 small 输入长度，请先分块或缩短调查问题")
