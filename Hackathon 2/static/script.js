// Flip card behavior (click to flip)
document.addEventListener('click', function(e){
  if(e.target.classList.contains('flip-card') || e.target.closest('.flip-card')){
    const el = e.target.closest('.flip-card')
    const inner = el.querySelector('.flip-inner')
    inner.classList.toggle('flipped')
  }
})
