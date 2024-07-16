function copyToClipboard() {
    const code = document.querySelector('.code-box code').textContent;
    navigator.clipboard.writeText(code).then(() => {
      alert('Code copied to clipboard!');
    }, (err) => {
      console.error('Could not copy code: ', err);
    });
  }
  
  function downloadCode() {
    const code = document.querySelector('.code-box code').textContent;
    const blob = new Blob([code], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'script.ps1'; // Default file name
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
  