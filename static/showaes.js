window.onload = function()
{
	setInterval(function(){
		
		if (document.querySelector("#aes").checked ==true)
		{
			document.querySelector("#kluczaes").style.visibility = "visible";
		}
		else
		{
			document.querySelector("#kluczaes").style.visibility = "hidden";
		}
		
		
		},200)
	
	
}
