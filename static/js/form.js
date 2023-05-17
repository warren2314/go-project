document.getElementById('user-form').addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent the default form submission behavior

    var form = event.target;
    var formData = new FormData(form);

    fetch('/api/adduser', {
        method: 'POST',
        body: formData
    })
        .then(function(response) {
            if (response.ok) {
                return response.text(); // Parse the response as plain text
            } else {
                throw new Error('Failed to add user');
            }
        })
        .then(function(data) {
            // Display the success message
            form.reset();
            var successMessage = document.createElement('div');
            successMessage.textContent = 'User added successfully';
            form.parentNode.appendChild(successMessage);
        })
        .catch(function(error) {
            console.error(error);
            var errorMessage = document.createElement('div');
            errorMessage.textContent = 'Failed to add user';
            form.parentNode.appendChild(errorMessage);
        });
});
