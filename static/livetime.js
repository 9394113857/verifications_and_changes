function updateLiveTime() {
    const liveTimeElement = document.getElementById('live-time');
    const now = new Date();
    const hours = now.getHours().toString().padStart(2, '0');
    const minutes = now.getMinutes().toString().padStart(2, '0');
    const seconds = now.getSeconds().toString().padStart(2, '0');
    const formattedTime = `Current Time: ${hours}:${minutes}:${seconds}`;
    liveTimeElement.textContent = formattedTime;
    setTimeout(updateLiveTime, 1000); // Update every second
}

document.addEventListener('DOMContentLoaded', updateLiveTime);
