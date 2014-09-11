# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# For more information, please refer to the LICENSE.txt file.

#Anubis Converter Script
#Updated 02/24/2014 for MAEC v4.1 and CybOX v2.1

#Anubis main parser class
#For use in extracting data from XML Anubis output
from maec.bundle.bundle import Bundle
from maec.bundle.malware_action import MalwareAction
from maec.bundle.av_classification import AVClassification, AVClassifications
from maec.package.analysis import Analysis, DynamicAnalysisMetadata
from maec.package.malware_subject import MalwareSubject
from maec.bundle.behavior import Behavior
from maec.bundle.process_tree import ProcessTree
import maec.utils
from cybox.utils import Namespace
from cybox.core.object import Object
from cybox.core.associated_object import AssociatedObject
from cybox.common.tools import ToolInformation
import anubis
import traceback

# test if a dictionary is empty,
# i.e., all properties are None or empty string
# TODO: detect empty lists
def empty_test(dic):
    for k,v in dic.items():
        # an xsi:type doesn't make a dictionary non-empty
        if k is "xsi:type": continue
        
        # if a non-empty property is found, it's not empty
        if v is not None and v is not "":
            return False
        
        if isinstance(v, dict):
            if not empty_test(v):
                return False

    return True


class parser:

    def __init__(self):
        #array for storing actions
        self.actions = []
        #the subject of the analysis (typically a PE binary)
        self.analysis_subject_md5 = ''
        self.analysis_subject_sha1 = ''
        #variable for keeping tab on the number of actions we parsed out
        self.number_of_actions = 0
        #the analysis object of the Anubis XML document
        self.analysis_object = None
        self.parent_process_id = 0
        self.version = ''
        #action ids
        self.action_ids = []
        self.actions = {}
        self.objects = {}
        self.maec_behaviors = {}
        self.maec_subjects = []
        self.maec_analysis = None
        self.analysis_subject_md5 = None
        self.analysis_subject_path = None
        self.analysis_subject_name = None
        self.tool_id = None
        self.subject_id_list = []
        
    #"Public" methods
    
    #Open and read-in the Anubis output file
    #This assumes that we're dealing with a XML file
    def open_file(self, infilename):
        try:
            self.analysis_object = anubis.parse(infilename)
            if self.analysis_object == None:
                return False
            else:
                return True
        except Exception, err:
           print('\nError: %s\n' % str(err))
           
    #Parse the XML document
    #Extract processes, actions, and information about the analysis subject
    def parse_document(self):
        #Get the analysis subjects
        analysis_subjects = self.analysis_object.get_analysis_subject()
        
        #Setup the action/object dictionaries
        self.__setup_dictionaries()

        # Instantiate the ID generator class (for automatic ID generation) with our example namespace
        NS = Namespace("https://github.com/MAECProject/anubis-to-maec", "AnubisToMAEC")
        maec.utils.set_id_namespace(NS)
        
        #Get the analysis config
        config = self.analysis_object.get_configuration()
        self.version = config.get_ttanalyze_version().get_prog_version()
        
        #create the process tree and do the additional processing
        self.__create_process_tree(analysis_subjects)
        return 1
                
    #accessor methods
    def get_processes(self):
        return self.processes
    
    def get_actions(self):
        return self.actions

    def get_analysis_subject(self):
        return self.analysis_subject

    def get_number_of_actions(self):
        return self.number_of_actions
        
    #"Private" methods
    def __setup_dictionaries(self):
        #setup the actions
        actions = {}
        actions['File System Actions'] = []
        actions['IPC Actions'] = []
        actions['Service Actions'] = []
        actions['Registry Actions'] = []
        actions['Network Actions'] = []
        actions['Process Actions'] = []
        actions['Driver Actions'] = []
        self.actions = actions
        
    #parse each process, create the process tree, and add any discovered actions/objects
    def __create_process_tree(self, analysis_subjects):
        id_map = {}
        process_tree = {}
        tool_id = None
        analysis_object = None
        
        malware_subject = None
        av_aliases = None
        
        # build process tree and create primary malware subject
        for analysis_subject in analysis_subjects:
            general_info = analysis_subject.get_general()
            analysis_reason = general_info.get_analysis_reason()
            
            #create and setup the analysis object if this is the primary subject
            if analysis_reason.lower().count("primary analysis subject") > 0 or analysis_reason.lower().count("primary analysis target") > 0:
                malware_subject = self.__create_malware_subject_object(analysis_subject, general_info, analysis_subjects, id_map)
                #create the maec analysis object
                        
                av_aliases = self.__get_av_aliases(analysis_subject)
                self.tool_id = malware_subject.analyses[0].tools[0].id_

            # create a process object and get all info about it
            current_process_obj = self.__create_analysis_process_object(analysis_subject, general_info, id_map, process_tree)
            
            if analysis_subject.get_activities() != None:
                self.__process_activities(analysis_subject.get_activities(), current_process_obj)
            
        #after all processes have been handled, add actions to the bundle
        self.bundle_obj = Bundle(False)
        for key, value in self.actions.items():
            if len(value) > 0:
                self.bundle_obj.add_named_action_collection(key)
            for action in value:
                self.bundle_obj.add_action(action, key)
                
        for alias in av_aliases:
            self.bundle_obj.add_av_classification(AVClassification.from_dict(alias))

        self.bundle_obj.set_process_tree(ProcessTree.from_dict(process_tree))

        malware_subject.add_findings_bundle(self.bundle_obj)
        malware_subject.analyses[0].set_findings_bundle(self.bundle_obj.id_)
        
        self.maec_subjects.append(malware_subject)
        
        
    def __create_malware_subject_object(self, analysis_subject, general_info, analysis_subjects, id_map):
        #first, extract the info from the object
        obj_id = general_info.get_id()
        parent_obj_id = general_info.get_parent_id()
        file = general_info.get_virtual_fn()
        path = general_info.get_virtual_path()
        self.parent_process_id = general_info.get_id()
        md5 = None
        sha1 = None
        file_size = None
        packer = None
        arguments = None
        exit_code = None
        dll_dependencies = None
        if general_info.get_md5() != None: md5 = general_info.get_md5()
        if general_info.get_sha1() != None: sha1 = general_info.get_sha1()
        if general_info.get_file_size() != None: file_size = general_info.get_file_size()
        if general_info.get_arguments() != None: arguments = general_info.get_arguments()
        if general_info.get_exit_code() != None: exit_code = general_info.get_exit_code()
        if analysis_subject.get_sigbuster() != None: packer = analysis_subject.get_sigbuster()
        if analysis_subject.get_dll_dependencies() != None: dll_dependencies = analysis_subject.get_dll_dependencies()
        av_aliases = self.__get_av_aliases(analysis_subject) 
        
        #create the analysis subject object
        malware_subject_object = MalwareSubject()
        
        #Create the file object and add the attributes
        object_dict = {}
        object_dict['id'] = maec.utils.idgen.create_id(prefix="object")
        self.subject_id_list.append(object_dict['id'])
        
        file_dict = {}
        file_dict['xsi:type'] = 'WindowsExecutableFileObjectType'
        if file_size != None:
            file_dict['size_in_bytes'] = file_size
        if packer != None and len(packer.strip()) > 0:
            split_packer = packer.split(' ')
            if len(split_packer) == 2:
                packer = { 'name' : split_packer[0], 'version' : split_packer[1] }
            else:
                packer = { 'name' : split_packer[0] }
            file_dict['packer_list'] = [packer]
        if md5 != None or sha1 != None:
            hashes = []
            if md5 != None:
                hash_dict =  {'type' : {'value' :'MD5', 'datatype' : 'string', 'force_datatype' : True},
                              'simple_hash_value': {'value' : md5}
                             }
                hashes.append(hash_dict)
            if sha1 != None:
                hash_dict =  {'type' : {'value' :'SHA1', 'datatype' : 'string', 'force_datatype' : True},
                              'simple_hash_value': {'value' : sha1}
                             }
                hashes.append(hash_dict)
            if len(hashes) > 0:
                file_dict['hashes'] = hashes
        if dll_dependencies != None:
            pe_attributes = {}
            pe_imports = []
            for loaded_dll in dll_dependencies.get_loaded_dll():
                pe_import = {}
                pe_import['file_name'] = loaded_dll.get_full_name()
                pe_import['virtual_address'] = loaded_dll.get_base_address().lstrip('0x')
                pe_import['delay_load'] = not bool(int(loaded_dll.get_is_load_time_dependency()))
                pe_imports.append(pe_import)
            if len(pe_imports) > 0:
                pe_attributes['imports'] = pe_imports
            if len(pe_attributes):
                file_dict['pe_attributes'] = pe_attributes
        
        # create the analysis and add it to the subject
        analysis = Analysis()
        analysis.type_ = 'triage'
        analysis.method = 'dynamic'
        analysis.add_tool(ToolInformation.from_dict({'id' :
          maec.utils.idgen.create_id(prefix="tool"),
                           'vendor' : 'ISECLab', 
                           'name' : 'TTAnalyze' }))
        
        dynamic_analysis = {}
        if arguments != None:
            dynamic_analysis['command_line'] = arguments.strip()
        if exit_code != None:
            dynamic_analysis['exit_code'] = exit_code
        
        if len(dynamic_analysis) > 0:
            analysis.dynamic_analysis_metadata = DynamicAnalysisMetadata.from_dict(dynamic_analysis)
            
        malware_subject_object.add_analysis(analysis)
        
        #set the object as the defined object
        object_dict['properties'] = file_dict
        
        #bind the object to the analysis subject object
        malware_subject_object.set_malware_instance_object_attributes(Object.from_dict(object_dict))
        
        return malware_subject_object
    
    def __create_analysis_process_object(self, analysis_subject, general_info, id_map, process_tree):
        #first, extract the info from the object
        obj_id = general_info.get_id()
        parent_obj_id = general_info.get_parent_id()
        file = general_info.get_virtual_fn()
        path = general_info.get_virtual_path()
        self.parent_process_id = general_info.get_id()
        md5 = None
        sha1 = None
        file_size = None
        packer = None
        arguments = None
        exit_code = None
        dll_dependencies = None
        if general_info.get_md5() != None: md5 = general_info.get_md5()
        if general_info.get_sha1() != None: sha1 = general_info.get_sha1()
        if general_info.get_file_size() != None: file_size = general_info.get_file_size()
        if general_info.get_arguments() != None: arguments = general_info.get_arguments()
        if general_info.get_exit_code() != None: exit_code = general_info.get_exit_code()
        if analysis_subject.get_sigbuster() != None: packer = analysis_subject.get_sigbuster()
        if analysis_subject.get_dll_dependencies() != None: dll_dependencies = analysis_subject.get_dll_dependencies()

        #create the process object and add the attributes
        process_attributes = {}
        associated_object_dict = {  'id' :
        maec.utils.idgen.create_id(prefix="object")}
        
        process_attributes['xsi:type'] = 'WindowsProcessObjectType'
        process_attributes['name'] = file
        process_attributes['id'] = maec.utils.idgen.create_id(prefix="process_tree_node")
        process_attributes['image_info'] = { 'path' : { 'value' : path } }
        if arguments != None:
            process_attributes['image_info']['argument_list'] = arguments
        
        process_attributes['initiated_actions'] = []
        process_attributes['spawned_process'] = []
        
        if parent_obj_id == 1:
            process_tree['root_process'] = process_attributes
        else:
            parent_process = id_map.get(parent_obj_id)
            parent_process['spawned_process'].append(process_attributes)
        
        #add the object to the id map
        id_map[obj_id] = process_attributes
        
        return process_attributes
    
    def __process_activities(self, activities, current_process_obj):
        if activities.get_file_activities() != None:
            for file_activity in activities.get_file_activities():
                self.__process_file_activities(file_activity, current_process_obj)
        if activities.get_registry_activities() != None:
            for registry_activity in activities.get_registry_activities():
                self.__process_registry_activities(registry_activity, current_process_obj)
        if activities.get_service_activities() != None:
            for service_activity in activities.get_service_activities():
                self.__process_service_activities(service_activity, current_process_obj)
        if activities.get_network_activities() != None:
            for network_activity in activities.get_network_activities():
                self.__process_network_activities(network_activity, current_process_obj)
        if activities.get_process_activities() != None:
            for process_activity in activities.get_process_activities():
                self.__process_process_activities(process_activity, current_process_obj)                 
        if activities.get_misc_activities() != None:
            for misc_activity in activities.get_misc_activities():
                self.__process_misc_activities(misc_activity, current_process_obj)
        
    def __process_file_activities(self, file_activity, current_process_obj):
        for deleted_file in file_activity.get_file_deleted():
            file_attributes = {}
            associated_object_dict = {  'id' :
                maec.utils.idgen.create_id(prefix="object")}
            
            filename = deleted_file.get_name()
            if filename.count(',') > 0:
                filename = filename.split(',')[0]
            
            split_filename = filename.split('\\')
            actual_filename = split_filename[len(split_filename)-1]
            filepath = filename.rstrip(actual_filename)
            
            is_pipe = split_filename[0] == 'PIPE' or filename.lower().count('pipe') > 0
            
            # define file attributes
            if is_pipe:
                file_attributes['xsi:type'] = "PipeObjectType"
                file_attributes['named'] = True
                file_attributes['name'] = split_filename[1]
            else:
                file_attributes['xsi:type'] = "FileObjectType"
                fully_qualified = True
                if "%" in filename:
                    fully_qualified = False
                file_attributes['file_path'] = { 'value' : filename, 'fully_qualified' : fully_qualified }
            
            if empty_test(file_attributes): continue
            
            # defined associated object
            associated_object_dict['properties'] = file_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['associated_objects'] = [associated_object_dict]
            
            if not is_pipe:
                action_attributes['name'] = {'value' : 'delete file', 'xsi:type' : 'maecVocabs:FileActionNameVocab-1.0'}
            else:
                action_attributes['name'] = {'value' : 'delete named pipe', 'xsi:type' : 'maecVocabs:IPCActionNameVocab-1.0'}

            fs_action = MalwareAction.from_dict(action_attributes)
            
            self.actions.get('File System Actions').append(fs_action)
            
            current_process_obj['initiated_actions'].append(fs_action.id_)
            
        for created_file in file_activity.get_file_created():
            file_attributes = {}
            associated_object_dict = {  'id' :
                maec.utils.idgen.create_id(prefix="object")}
            
            filename = created_file.get_name()
            if filename.count(',') > 0:
                filename = filename.split(',')[0]
            split_filename = filename.split('\\')
            actual_filename = split_filename[len(split_filename)-1]
            filepath = filename.rstrip(actual_filename)
            
            is_pipe = split_filename[0] == 'PIPE' or filename.lower().count('pipe') > 0
            
            if is_pipe:
                file_attributes['xsi:type'] = "PipeObjectType"
                file_attributes['named'] = True
                file_attributes['name'] = split_filename[1]
            else:
                file_attributes['xsi:type'] = "FileObjectType"
                fully_qualified = True
                if "%" in filename:
                    fully_qualified = False
                file_attributes['file_path'] = { 'value' : filename, 'fully_qualified' : fully_qualified }

            if empty_test(file_attributes): continue

            associated_object_dict['properties'] = file_attributes
            associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['associated_objects'] = [associated_object_dict]
            
            if not is_pipe:
                action_attributes['name'] = {'value' : 'create file', 'xsi:type' : 'maecVocabs:FileActionNameVocab-1.0'}
            else:
                action_attributes['name'] = {'value' : 'create named pipe', 'xsi:type' : 'maecVocabs:IPCActionNameVocab-1.0'}
            
            fs_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('File System Actions').append(fs_action)
            current_process_obj['initiated_actions'].append(fs_action.id_)


        for read_file in file_activity.get_file_read():
            file_attributes = {}
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            filename = read_file.get_name()
            if filename.count(',') > 0:
                split_filename = filename.split(',')[0].split('\\')
                filename = filename.split(',')[0]
            else:
                split_filename = filename.split('\\')
            actual_filename = split_filename[len(split_filename)-1]
            filepath = filename.rstrip(actual_filename)
            
            is_pipe = split_filename[0] == 'PIPE' or filename.lower().count('pipe') > 0
            
            if is_pipe:
                file_attributes['xsi:type'] = "PipeObjectType"
                file_attributes['named'] = True
                file_attributes['name'] = split_filename[1]
            else:
                file_attributes['xsi:type'] = "FileObjectType"
                fully_qualified = True
                if "%" in filename:
                    fully_qualified = False
                file_attributes['file_path'] = { 'value' : filename, 'fully_qualified' : fully_qualified }
                
            if empty_test(file_attributes): continue
                
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict['properties'] = file_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['associated_objects'] = [associated_object_dict]
            
            if not is_pipe:
                action_attributes['name'] = {'value' : 'read from file', 'xsi:type' : 'maecVocabs:FileActionNameVocab-1.0'}
            else:
                action_attributes['name'] = {'value' : 'read from named pipe', 'xsi:type' : 'maecVocabs:IPCActionNameVocab-1.0'}

            fs_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('File System Actions').append(fs_action)
            current_process_obj['initiated_actions'].append(fs_action.id_)
            
            
        for modified_file in file_activity.get_file_modified():
            file_attributes = {}
            filename = modified_file.get_name()
            if filename.count(',') > 0:
                split_filename = filename.split(',')[0].split('\\')
                filename = filename.split(',')[0]
            else:
                split_filename = filename.split('\\')
            actual_filename = split_filename[len(split_filename)-1]
            filepath = filename.rstrip(actual_filename)
            
            is_pipe = split_filename[0] == 'PIPE' or filename.lower().count('pipe') > 0
            
            if is_pipe:
                file_attributes['xsi:type'] = "PipeObjectType"
                file_attributes['named'] = True
                file_attributes['name'] = split_filename[1]
            else:
                file_attributes['xsi:type'] = "FileObjectType"
                fully_qualified = True
                if "%" in filename:
                    fully_qualified = False
                file_attributes['file_path'] = { 'value' : filename, 'fully_qualified' : fully_qualified }
                
            if empty_test(file_attributes): continue
                
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = file_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['associated_objects'] = [associated_object_dict]
            
            if not is_pipe:
                action_attributes['name'] = {'value' : 'modify file', 'xsi:type' : 'maecVocabs:FileActionNameVocab-1.0'}
            else:
                action_attributes['name'] = {'value' : 'write to named pipe', 'xsi:type' : 'maecVocabs:IPCActionNameVocab-1.0'}

            fs_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('File System Actions').append(fs_action)
            current_process_obj['initiated_actions'].append(fs_action.id_)
                
        for renamed_file in file_activity.get_file_renamed():
            file_attributes_old = {}
            associated_object_dict_old = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            filename_old = renamed_file.get_old_name()
            file_attributes_old['xsi:type'] = "FileObjectType"
            file_attributes_old['file_path'] = { 'value' : filename_old }
                
            file_attributes_new = {}
            associated_object_dict_new = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            filename_new = renamed_file.get_new_name()
            file_attributes_new['xsi:type'] = "FileObjectType"
            file_attributes_new['file_path'] = { 'value' : filename_new }

            #Generate the MAEC objects and actions
            #First, create the objects
            associated_object_dict_old['properties'] = file_attributes_old
            associated_object_dict_old['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}
            associated_object_dict_new['properties'] = file_attributes_new
            associated_object_dict_new['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['associated_objects'] = [associated_object_dict_old, associated_object_dict_new]
            
            action_attributes['name'] = {'value' : 'rename file', 'xsi:type' : 'maecVocabs:FileActionNameVocab-1.0'}

            fs_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('File System Actions').append(fs_action)
            current_process_obj['initiated_actions'].append(fs_action.id_)
    
    def __process_registry_activities(self, registry_activity, current_process_obj):
        for created_regkey in registry_activity.get_reg_key_created():
            regkey_attributes = {}
            split_name = created_regkey.get_name().split('\\')
            regkey_attributes['hive'] = self.__map_reg_hive_string(split_name[0])
            actual_key = ''
            for i in range(1, len(split_name)):
                actual_key += (split_name[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['xsi:type'] = "WindowsRegistryKeyObjectType"
            regkey_attributes['key'] = actual_key
            
            if empty_test(regkey_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = regkey_attributes
            associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Generate the MAEC action
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'create registry key', 'xsi:type' : 'maecVocabs:RegistryActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            reg_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Registry Actions').append(reg_action)
            current_process_obj['initiated_actions'].append(reg_action.id_)
            
        for opened_regkey in registry_activity.get_reg_key_created_or_opened():
            regkey_attributes = {}
            split_name = opened_regkey.get_name().split('\\')
            regkey_attributes['hive'] = self.__map_reg_hive_string(split_name[0])
            actual_key = ''
            for i in range(1, len(split_name)):
                actual_key += (split_name[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['xsi:type'] = "WindowsRegistryKeyObjectType"
            regkey_attributes['key'] = actual_key
            regkey_attributes['type'] = 'Key/Key Group'
            
            if empty_test(regkey_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = regkey_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Generate the MAEC action
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'open registry key', 'xsi:type' : 'maecVocabs:RegistryActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            reg_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Registry Actions').append(reg_action)
            current_process_obj['initiated_actions'].append(reg_action.id_)
        
        for deleted_regkey in registry_activity.get_reg_key_deleted():
            regkey_attributes = {}
            split_name = deleted_regkey.get_name().split('\\')
            regkey_attributes['hive'] = self.__map_reg_hive_string(split_name[0])
            actual_key = ''
            for i in range(1, len(split_name)):
                actual_key += (split_name[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['xsi:type'] = "WindowsRegistryKeyObjectType"
            regkey_attributes['key'] = actual_key
            regkey_attributes['type'] = 'Key/Key Group'
            
            if empty_test(regkey_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = regkey_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Generate the MAEC action
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'delete registry key', 'xsi:type' : 'maecVocabs:RegistryActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            reg_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Registry Actions').append(reg_action)
            current_process_obj['initiated_actions'].append(reg_action.id_)
        
        for deleted_regkeyvalue in registry_activity.get_reg_value_deleted():
            regkey_attributes = {}
            split_name = deleted_regkeyvalue.get_key().split('\\')
            regkey_attributes['hive'] = self.__map_reg_hive_string(split_name[0])
            actual_key = ''
            for i in range(1, len(split_name)):
                actual_key += (split_name[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['xsi:type'] = "WindowsRegistryKeyObjectType"
            regkey_attributes['key'] = actual_key
            regkey_attributes['value'] = [{ 'name' : deleted_regkeyvalue.get_value_name() }]
            regkey_attributes['type'] = 'Key/Key Group'
            
            if empty_test(regkey_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = regkey_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Generate the MAEC action
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'delete registry key value', 'xsi:type' : 'maecVocabs:RegistryActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            reg_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Registry Actions').append(reg_action)
            current_process_obj['initiated_actions'].append(reg_action.id_)
            
        for modified_regvalue in registry_activity.get_reg_value_modified():
            regkey_attributes = {}
            split_name = modified_regvalue.get_key().split('\\')
            regkey_attributes['hive'] = self.__map_reg_hive_string(split_name[0])
            actual_key = ''
            for i in range(1, len(split_name)):
                actual_key += (split_name[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['key'] = actual_key
            
            if modified_regvalue.get_value_name() is not "" or modified_regvalue.get_value_data() is not "":
                regkey_attributes['values'] = [{}]
            if modified_regvalue.get_value_data() is not "":
                regkey_attributes['values'] = [{ 'data' : modified_regvalue.get_value_data() }]
            if modified_regvalue.get_value_name() is not "":
                regkey_attributes['values'][0]['name'] = modified_regvalue.get_value_name()
            regkey_attributes['xsi:type'] = "WindowsRegistryKeyObjectType"
            regkey_attributes['type'] = 'Key/Key Group'
            
            if empty_test(regkey_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = regkey_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Generate the MAEC action
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'modify registry key value', 'xsi:type' : 'maecVocabs:RegistryActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            reg_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Registry Actions').append(reg_action)
            current_process_obj['initiated_actions'].append(reg_action.id_)
        
        for read_regvalue in registry_activity.get_reg_value_read():
            regkey_attributes = {}
            split_name = read_regvalue.get_key().split('\\')
            regkey_attributes['hive'] = self.__map_reg_hive_string(split_name[0])
            actual_key = ''
            for i in range(1, len(split_name)):
                actual_key += (split_name[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['key'] = actual_key
            if read_regvalue.get_value_name() is not "" or read_regvalue.get_value_data() is not "":
                regkey_attributes['values'] = [{}]
            if read_regvalue.get_value_data() is not "":
                regkey_attributes['values'] = [{ 'data' : read_regvalue.get_value_data() }]
            if read_regvalue.get_value_name() is not "":
                regkey_attributes['values'][0]['name'] = read_regvalue.get_value_name()
            regkey_attributes['xsi:type'] = "WindowsRegistryKeyObjectType"
            regkey_attributes['type'] = 'Key/Key Group'
            
            if empty_test(regkey_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = regkey_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Generate the MAEC action
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'read registry key value', 'xsi:type' : 'maecVocabs:RegistryActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            reg_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Registry Actions').append(reg_action)
            current_process_obj['initiated_actions'].append(reg_action.id_)
            
        for monitored_regkey in registry_activity.get_reg_key_monitored():
            regkey_attributes = {}
            split_name = read_regvalue.get_key().split('\\')
            regkey_attributes['hive'] = self.__map_reg_hive_string(split_name[0])
            actual_key = ''
            for i in range(1, len(split_name)):
                actual_key += (split_name[i] + '\\')
            actual_key = actual_key.rstrip('\\')
            regkey_attributes['key'] = actual_key
            regkey_attributes['xsi:type'] = "WindowsRegistryKeyObjectType"
            regkey_attributes['type'] = 'Key/Key Group'
            
            if empty_test(regkey_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = regkey_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Generate the MAEC action
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'monitor registry key', 'xsi:type' : 'maecVocabs:RegistryActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            reg_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Registry Actions').append(reg_action)
            current_process_obj['initiated_actions'].append(reg_action.id_)
            
    def __map_reg_hive_string(self, input):
        if input == 'HKU':
            return 'HKEY_USERS'
        elif input == 'HKLM':
            return 'HKEY_LOCAL_MACHINE'
        elif input == 'HKCR':
            return 'HKEY_CLASSES_ROOT'
        elif input == 'HKCC':
            return 'HKEY_CURRENT_CONFIG'
        elif input == 'HKCU':
            return 'HKEY_CURRENT_USER'
            
    def __process_service_activities(self, service_activity, current_process_obj):
        for started_service in service_activity.get_service_started():
            service_attributes = {}
            service_attributes['xsi:type'] = 'WindowsServiceObjectType'
            service_attributes['name'] = started_service.get_name()
            
            if empty_test(service_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = service_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'start service', 'xsi:type' : 'maecVocabs:ServiceActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            action_attributes['tool_id'] = self.tool_id
            service_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Service Actions').append(service_action)
            current_process_obj['initiated_actions'].append(service_action.id_)
        
        for created_service in service_activity.get_service_created():
            service_attributes = {}
            service_attributes['xsi:type'] = 'WindowsServiceObjectType'
            service_attributes['name'] = created_service.get_name()
            service_attributes['image_info'] = {'path' : { 'value' : created_service.get_path() } }
            
            if empty_test(service_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = service_attributes
            associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'create service', 'xsi:type' : 'maecVocabs:ServiceActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            action_attributes['tool_id'] = self.tool_id
            service_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Service Actions').append(service_action)
            current_process_obj['initiated_actions'].append(service_action.id_)
            
        for deleted_service in service_activity.get_service_deleted():
            service_attributes = {}
            service_attributes['xsi:type'] = 'WindowsServiceObjectType'
            service_attributes['name'] = deleted_service.get_name()
            
            if empty_test(service_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = service_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'delete service', 'xsi:type' : 'maecVocabs:ServiceActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            action_attributes['tool_id'] = self.tool_id
            service_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Service Actions').append(service_action)
            current_process_obj['initiated_actions'].append(service_action.id_)
        
        for changed_service in service_activity.get_service_changed():
            service_attributes = {}
            service_attributes['xsi:type'] = 'WindowsServiceObjectType'
            service_attributes['name'] = changed_service.get_name()
            
            if empty_test(service_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = service_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'modify service configuration', 'xsi:type' : 'maecVocabs:ServiceActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            action_attributes['tool_id'] = self.tool_id
            service_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Service Actions').append(service_action)
            current_process_obj['initiated_actions'].append(service_action.id_)

        # python-cybox does not yet support control codes
        '''for control_code in service_activity.get_service_control_code():
            service_attributes = {}
            service_attributes['name'] = control_code.get_service()
            service_attributes['controlcode'] = control_code.get_control_code()
            service_attributes['association'] = 'Affected'
            #Generate the MAEC objects and actions
            #First, create the object
            service_object = self.maec_object.create_service_object(service_attributes)

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['defined_action_name'] = 'Modify Service'
            action_attributes['action_type'] = 'Send'
            action_attributes['object'] = service_object
            action_attributes['initiator_id'] = current_maec_id
            action_attributes['tool_id'] = self.tool_id
            action_attributes['context'] = 'Host'
            service_action = self.maec_action.create_action(action_attributes)
            self.actions.get('Service Actions').append(service_action)
            self.action_ids.append(service_action.get_id())'''
            
    def __process_network_activities(self, network_activity, current_process_obj): 
        for sockets in network_activity.get_sockets():
            for socket in sockets.get_socket():
                connection_attributes = {
                    'xsi:type' : 'NetworkConnectionObjectType',
                    'source_socket_address': {
                        'ip_address': {'address_value' : socket.get_local_ip(),
                                       'is_source' : True },
                        'port': { 'port_value' : socket.get_local_port() }
                    },
                    'destination_socket_address': {
                        'ip_address': {'address_value' : socket.get_foreign_ip(),
                                       'is_source' : False },
                        'port': { 'port_value' : socket.get_foreign_port() }
                    },
                    'layer4_protocol' : {'value':socket.get_type(), 'force_datatype':True}
                }
                
                if socket.get_foreign_ip() is "":
                    connection_attributes['destination_socket_address'].pop('ip_address')

                if empty_test(connection_attributes): continue

                #Generate the MAEC objects and actions
                #First, create the object
                associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
                associated_object_dict['properties'] = connection_attributes
                associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

                #Next, create the action (that operated on the object)
                action_attributes = {}
                action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
                action_attributes['name'] = {'value' : 'connect to socket address', 'xsi:type' : 'maecVocabs:NetworkActionNameVocab-1.0'}
                action_attributes['associated_objects'] = [associated_object_dict]
                socket_action = MalwareAction.from_dict(action_attributes)
                self.actions.get('Network Actions').append(socket_action)
                current_process_obj['initiated_actions'].append(socket_action.id_)

                
    def __process_process_activities(self, process_activity, current_process_obj):
        for created_process in process_activity.get_process_created():
            process_attributes = {}
            process_attributes['xsi:type'] = 'WindowsProcessObjectType'
            
            if created_process.get_cmd_line() is not "" or created_process.get_exe_name() is not "":
                process_attributes['image_info'] = {}
            if created_process.get_exe_name() is not "":
                process_name = created_process.get_exe_name()
                process_attributes['image_info']['path'] = { 'value': process_name }
                process_attributes['name'] = { 'value': process_name.split('\\')[-1] }
            if created_process.get_cmd_line() is not "":
                process_attributes['image_info']['command_line'] = created_process.get_cmd_line()

            if empty_test(process_attributes): continue

            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = process_attributes
            associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'create process', 'xsi:type' : 'maecVocabs:ProcessActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            process_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Process Actions').append(process_action)
            current_process_obj['initiated_actions'].append(process_action.id_)
            
        for killed_process in process_activity.get_process_killed():
            process_attributes = {}
            process_attributes['xsi:type'] = 'WindowsProcessObjectType'
            process_attributes['name'] = killed_process.get_name()
            
            if empty_test(process_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = process_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'kill process', 'xsi:type' : 'maecVocabs:ProcessActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            process_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Process Actions').append(process_action)
            current_process_obj['initiated_actions'].append(process_action.id_)
        
        for created_remote_thread in process_activity.get_remote_thread_created():
            process_path = created_remote_thread.get_process()
            process_attributes = {}
            process_attributes['xsi:type'] = 'WindowsProcessObjectType'
            process_attributes['name'] = process_path.split("\\")[-1]
            process_attributes['image_info'] = {}
            process_attributes['image_info']['path'] = { 'value': process_path }
            
            if empty_test(process_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = process_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'create remote thread in process', 'xsi:type' : 'maecVocabs:ProcessThreadActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            process_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Process Actions').append(process_action)
            current_process_obj['initiated_actions'].append(process_action.id_)
            
        for mem_read in process_activity.get_foreign_mem_area_read():
            process_path = mem_read.get_process()
            
            if process_path is "": continue
            
            process_attributes = {}
            process_attributes['xsi:type'] = 'WindowsProcessObjectType'
            process_attributes['name'] = process_path.split("\\")[-1]
            process_attributes['image_info'] = {}
            process_attributes['image_info']['path'] = { 'value': process_path }
            
            if empty_test(process_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = process_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'read from process memory', 'xsi:type' : 'maecVocabs:ProcessMemoryActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            process_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Process Actions').append(process_action)
            current_process_obj['initiated_actions'].append(process_action.id_)
            
        for mem_write in process_activity.get_foreign_mem_area_write():
            process_path = mem_write.get_process()
            process_attributes = {}
            process_attributes['xsi:type'] = 'WindowsProcessObjectType'
            process_attributes['name'] = process_path.split("\\")[-1]
            process_attributes['image_info'] = {}
            process_attributes['image_info']['path'] = { 'value': process_path }
            
            if empty_test(process_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = process_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'write to process memory', 'xsi:type' : 'maecVocabs:ProcessMemoryActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            process_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Process Actions').append(process_action)
            current_process_obj['initiated_actions'].append(process_action.id_)
            
    def __process_misc_activities(self, misc_activity, current_process_obj):
        for created_mutex in misc_activity.get_mutex_created():
            mutex_attributes = {}
            mutex_attributes['xsi:type'] = "WindowsMutexObjectType"
            mutex_attributes['name']  = created_mutex.get_name()

            if empty_test(mutex_attributes): continue

            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = mutex_attributes
            associated_object_dict['association_type'] = {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'create mutex', 'xsi:type' : 'maecVocabs:SynchronizationActionNameVocab-1.0'}
            action_attributes['associated_objects'] = [associated_object_dict]
            mutex_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('IPC Actions').append(mutex_action)
            current_process_obj['initiated_actions'].append(mutex_action.id_)
            
    
        for loaded_driver in misc_activity.get_driver_loaded():
            driver_attributes = {}
            driver_attributes['xsi:type'] = 'WindowsDriverObjectType'
            driver_attributes['driver_name'] = loaded_driver.get_name()
            
            if empty_test(driver_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = driver_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'load driver', 'xsi:type': 'maecVocabs:DeviceDriverActionNameVocab-1.0' }
            action_attributes['associated_objects'] = [associated_object_dict]
            driver_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Driver Actions').append(driver_action)
            current_process_obj['initiated_actions'].append(driver_action.id_)

        for unloaded_driver in misc_activity.get_driver_unloaded():
            driver_attributes = {}
            driver_attributes['xsi:type'] = 'WindowsDriverObjectType'
            driver_attributes['driver_name'] = unloaded_driver.get_name()
            
            if empty_test(driver_attributes): continue
            
            #Generate the MAEC objects and actions
            #First, create the object
            associated_object_dict = { 'id' : maec.utils.idgen.create_id(prefix="object") }
            associated_object_dict['properties'] = driver_attributes
            associated_object_dict['association_type'] = {'value' : 'input', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}

            #Next, create the action (that operated on the object)
            action_attributes = {}
            action_attributes['id'] = maec.utils.idgen.create_id(prefix="action")
            action_attributes['name'] = {'value' : 'load driver', 'xsi:type': 'maecVocabs:DeviceDriverActionNameVocab-1.0' }
            action_attributes['associated_objects'] = [associated_object_dict]
            driver_action = MalwareAction.from_dict(action_attributes)
            self.actions.get('Driver Actions').append(driver_action)
            current_process_obj['initiated_actions'].append(driver_action.id_)
    
    def __get_av_aliases(self, object):
        av_classification_objects = [] 

        ikarus_scanner = object.get_ikarus_scanner()
        if ikarus_scanner != None:
            for sig in ikarus_scanner.get_sig():
                name = sig.get_name()
                av_classification_object = { 'classification_name' : name, 'vendor' : 'Ikarus' }
                av_classification_objects.append(av_classification_object)
        
        return av_classification_objects
