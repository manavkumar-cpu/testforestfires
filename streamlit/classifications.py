import streamlit as st
import pandas as pd
from sklearn.datasets import load_iris
from sklearn.ensemble import RandomForestClassifier

def load():
    iris=load_iris()
    df=pd.DataFrame(iris.data,columns=iris.feature_names)
    df['species']=iris.target
    return df,iris.target_names

df,target_names=load()

model=RandomForestClassifier()
model.fit(df.iloc[:,:-1],df['species'])


st.sidebar.title("sepal pepal")
sepal_length = st.sidebar.slider(
    "sepal length",
    float(df["sepal length (cm)"].min()),
    float(df["sepal length (cm)"].max()),
    float(df["sepal length (cm)"].mean())
)
sepal_width = st.sidebar.slider(
    "sepal width",
    float(df["sepal width (cm)"].min()),
    float(df["sepal width (cm)"].max()),
    float(df["sepal width (cm)"].mean())
)
petal_length = st.sidebar.slider(
    "petal length",
    float(df["petal length (cm)"].min()),
    float(df["petal length (cm)"].max()),
    float(df["petal length (cm)"].mean())
)
petal_width = st.sidebar.slider(
    "petal width",
    float(df["petal width (cm)"].min()),
    float(df["petal width (cm)"].max()),
    float(df["petal width (cm)"].mean())
)  

input_data=[sepal_length,sepal_width,petal_length,petal_width]

prediction=model.predict([input_data])
predicted_species=target_names[prediction][0]

st.write("The predicted species is:",predicted_species)