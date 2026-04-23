"""NyxOS PDF Exporter — HTML to PDF via WeasyPrint."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from loguru import logger


class PDFExporter:
    """Exports rendered HTML content to PDF using WeasyPrint."""

    def __init__(self) -> None:
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """Check whether WeasyPrint can be imported."""
        if self._available is not None:
            return self._available
        try:
            import weasyprint  # noqa: F401
            self._available = True
            logger.debug("WeasyPrint is available")
        except ImportError:
            self._available = False
            logger.debug("WeasyPrint is NOT available")
        except Exception as exc:
            self._available = False
            logger.warning("WeasyPrint probe failed: {}", exc)
        return self._available

    def export(self, html_content: str, output_path: str) -> str:
        """Convert rendered HTML to PDF. Returns output file path."""
        if not self.is_available():
            raise RuntimeError(
                "WeasyPrint is not installed. "
                "Install with: pip install weasyprint"
            )
        output = Path(output_path).expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            from weasyprint import HTML as WeasyHTML
            logger.info("Generating PDF -> {}", output)
            document = WeasyHTML(string=html_content)
            document.write_pdf(str(output))
            logger.info("PDF written ({} bytes)", output.stat().st_size)
            return str(output)
        except ImportError as exc:
            raise RuntimeError("WeasyPrint import failed.") from exc
        except OSError as exc:
            logger.error("Failed to write PDF: {}", exc)
            raise
        except Exception as exc:
            logger.error("PDF generation failed: {}", exc)
            raise RuntimeError("PDF generation failed: " + str(exc)) from exc
