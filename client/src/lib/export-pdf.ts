/**
 * Client-side PDF export utility
 * Opens branded HTML report in a new window for Print-to-PDF
 */

export function exportToPdf(html: string, filename: string): void {
  const printWindow = window.open("", "_blank");
  if (!printWindow) {
    // Fallback: download as HTML
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename.replace(".html", ".html");
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    return;
  }

  printWindow.document.write(html);
  printWindow.document.close();

  // Wait for fonts and styles to load, then trigger print
  printWindow.onload = () => {
    setTimeout(() => {
      printWindow.print();
    }, 500);
  };
}

export function downloadHtml(html: string, filename: string): void {
  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
