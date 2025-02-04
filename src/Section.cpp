
Section::~Section(){
    if(bytes){
        delete bytes;
    }
}
