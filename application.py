import pickle
import numpy as np
import pandas as pd
from flask import Flask,request,jsonify,render_template
from sklearn.preprocessing import StandardScaler
application=Flask(__name__)
app=application
ridge_model=pickle.load(open('models/ridge.pkl','rb'))
scaler=pickle.load(open('models/scaler.pkl','rb'))
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/predictdata', methods=['POST', 'GET'])
def predict_datapoint():
    if request.method == 'POST':
        try:
            # get values from form
            Temperature = float(request.form['Temperature'])
            RH = float(request.form['RH'])
            Ws = float(request.form['Ws'])
            Rain = float(request.form['Rain'])
            FFMC = float(request.form['FFMC'])
            DMC = float(request.form['DMC'])
            ISI = float(request.form['ISI'])
            Classes = float(request.form['Classes'])
            Region = float(request.form['Region'])

            # create input array (IMPORTANT: order must match training)
            data = [[Temperature, RH, Ws, Rain, FFMC, DMC, ISI, Classes, Region]]

            # scale input
            scaled_data = scaler.transform(data)

            # prediction
            result = ridge_model.predict(scaled_data)[0]

            return render_template('home.html', results=round(result, 2))

        except Exception as e:
            return f"Error: {e}"

    else:
        return render_template('home.html')
    
if __name__=='__main__':
    app.run(host="0.0.0.0",port=5000)
