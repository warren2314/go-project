function setupAjaxForm(formSelector, resultSelector) {
    $(formSelector).submit(function(event) {
        event.preventDefault();

        $.ajax({
            type: $(this).attr('method'),
            url: $(this).attr('action'),
            data: $(this).serialize(),
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
