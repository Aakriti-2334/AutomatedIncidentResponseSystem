document.addEventListener('DOMContentLoaded', function() {
    const socket = io(); // Connect to the honeypot's own backend
    const overlay = document.getElementById('animation-overlay');
    const startButton = document.getElementById('start-simulation-btn');
    const stopButton = document.getElementById('stop-simulation-btn');

    // --- Event Listeners for Buttons ---
    startButton.addEventListener('click', function() {
        console.log('Starting simulation...');
        startButton.disabled = true;
        stopButton.disabled = false;
        startButton.textContent = 'Simulation Running...';

        fetch('/api/start_simulation', { method: 'POST' })
            .then(response => response.json())
            .then(data => console.log(data.message))
            .catch(error => {
                console.error('Error starting simulation:', error);
                startButton.disabled = false;
                stopButton.disabled = true;
                startButton.textContent = 'Start Attack Simulation';
            });
    });

    stopButton.addEventListener('click', function() {
        console.log('Stopping simulation...');
        stopButton.disabled = true;
        startButton.disabled = false;
        startButton.textContent = 'Start Attack Simulation';

        fetch('/api/stop_simulation', { method: 'POST' })
            .then(response => response.json())
            .then(data => console.log(data.message))
            .catch(error => {
                console.error('Error stopping simulation:', error);
                // Re-enable stop button on error, as simulation might still be running
                stopButton.disabled = false;
            });
    });


    function showMaliciousIp(attackType, srcIp) {
        const ipElement = document.createElement('div');
        ipElement.className = 'malicious-ip';
        ipElement.innerHTML = `ATTACK DETECTED<br>${attackType}<br>FROM: ${srcIp}`;
        
        // Position the element randomly on the screen
        ipElement.style.top = `${Math.random() * 80 + 10}vh`;
        ipElement.style.left = `${Math.random() * 70 + 15}vw`;

        overlay.appendChild(ipElement);

        // Remove the element after the animation is complete (2.5s)
        setTimeout(() => {
            ipElement.remove();
        }, 2500);
    }

    // Listen for attack notifications from the server
    socket.on('attack_notification', function(attack) {
        console.log("Received attack notification:", attack.packet_data.attack_type);

        // If the attack is not "Normal", trigger the animation
        if (attack.packet_data.attack_type !== "Normal") {
            showMaliciousIp(attack.packet_data.attack_type, attack.packet_data.src_ip);
        }
    });
});
