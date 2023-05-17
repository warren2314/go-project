function setupAjaxForm(formSelector, resultSelector) {
    $(formSelector).submit(function(event) {
        event.preventDefault();

        // Get CSRF token from form
        var csrfToken = $(formSelector + " #csrfToken").val();

        $.ajax({
            type: $(this).attr('method'),
            url: $(this).attr('action'),
            data: $(this).serialize(),
            headers: {
                "X-CSRF-Token": csrfToken  // Set the CSRF token in the headers
            },
            success: function(data) {
                $(formSelector)[0].reset(); // Clear the form

                if (data.success) {
                    // Show a success message
                    $(resultSelector).removeClass().addClass('alert alert-success').html(data.message).fadeIn().delay(2000).fadeOut();
                } else {
                    // Show an error message
                    $(resultSelector).removeClass().addClass('alert alert-danger').html(data.message).fadeIn().delay(2000).fadeOut();
                }
            }
        });
    });
}
