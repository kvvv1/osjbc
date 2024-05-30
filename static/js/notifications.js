document.addEventListener('DOMContentLoaded', function() {
    const markAsViewedButtons = document.querySelectorAll('.mark-as-viewed');
  
    markAsViewedButtons.forEach(button => {
      button.addEventListener('click', function() {
        new Notification('Ordem de Serviço', {
          body: 'Um setor marcou a OS como vista!',
        });
      });
    });
  });
  