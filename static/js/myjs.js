function copyToClipboard() {
    // Function to copy the script content to the clipboard
    const scriptContent = "Your script content here"; // Replace with the actual script content
    const textarea = document.createElement("textarea");
    textarea.value = scriptContent;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);

    // Change icon to "Copied"
    const copyIcon = document.getElementById("copyIcon");
    copyIcon.innerText = "Copied";
    copyIcon.style.color = "milkwhite"; // Optional: Change the text color to indicate success

    // Revert back to icon after 3 seconds
    setTimeout(() => {
        copyIcon.innerHTML = ""; // Clear the current content
        copyIcon.className = "fe fe-copy fe-16"; // Reset to original icon
        copyIcon.style.color = ""; // Reset text color
    }, 3000);
}

function downloadCode() {
    // Function to download the script content as a file
    const scriptContent = "Your script content here"; // Replace with the actual script content
    const blob = new Blob([scriptContent], { type: "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "script.txt"; // Change the file name if needed
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}



