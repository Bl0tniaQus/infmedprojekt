#"Nadajnik"
import RPi.GPIO as GPIO
from flask import Flask
import time
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)
trigger=26		
echo=17
GPIO.setup(trigger,GPIO.OUT)
GPIO.setup(echo,GPIO.IN)

app = Flask(__name__)

@app.route("/czujnik", methods=["GET"])
def czujnik():
    time.sleep(1)
    GPIO.output(trigger,True)
    time.sleep(0.00001)
    GPIO.output(trigger,False)
    start=time.time()
    while GPIO.input(echo)==0:	
        start=time.time()
    while GPIO.input(echo)==1:
        stop=time.time()
    odleglosc = ((stop-start)*34300)/2
    return str(odleglosc)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
