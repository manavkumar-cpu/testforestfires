import streamlit as st

st.title("Hi there, everyone!")

name=st.text_input("maa baap ne jo naam diya hai wo yahan likh bho...ke :-")
if name:
    st.write("hello",name,"welcome to Gate Smashers")

age=st.slider("apni umar bataiyo bhai",0,100,25)

positions=["CowGirl","Missionary","Doggy Style","69","Spooning"]

position=st.selectbox("apni pasandida position chuno",positions)



    
if age>20:
    st.write("haan bol buddhe")
else:
    st.write("khada bhi hota hai tera Madarchod",position, "karega bkl")