<?php

if (!function_exists('CreateCategoryByNameIdent'))
{
function CreateCategoryByNameIdent($name, $Ident='', $ParentID=0, $pos=0, $hidden=false)
{
  global $_IPS;
  if ($Ident <> '') $Catid = @IPS_GetObjectIDByIdent ($Ident, $ParentID);
  if ($Ident == '') $Catid = @IPS_GetCategoryIDByName ($name, $ParentID);
  
  if($Catid === false)
  {
    $Catid = IPS_CreateCategory();
    IPS_SetParent($Catid, $ParentID);
    IPS_SetName($Catid, $name);
    IPS_SetPosition($Catid, $pos);
    IPS_SetHidden($Catid, $hidden);
    IPS_SetInfo($Catid, "This category was created by: #".$_IPS['SELF']."#");
  }
  return $Catid;
}
}

function SetVariable( $VarID, $Type, $Value )
{
	switch( $Type )
	{
	   case 0: // boolean
	      SetValueBoolean( $VarID, $Value );
	      break;
	   case 1: // integer
	      SetValueInteger( $VarID, $Value );
	      break;
	   case 2: // float
	      SetValueFloat( $VarID, $Value );
	      break;
	   case 3: // string
	      SetValueString( $VarID, $Value );
	      break;
	}
}
function CreateVariable( $Name, $Type, $Value, $Ident = '', $ParentID = 0 )
{
	//echo "CreateVariable: ( $Name, $Type, $Value, $Ident, $ParentID ) \n";
	if ( '' != $Ident )
	{
		$VarID = @IPS_GetObjectIDByIdent( $Ident, $ParentID );
		if ( false !== $VarID )
		{
		   SetVariable( $VarID, $Type, $Value );
		   return;
		}
	}
	$VarID = @IPS_GetObjectIDByName( $Name, $ParentID );
	if ( false !== $VarID ) // exists?
	{
	   $Obj = IPS_GetObject( $VarID );
	   if ( 2 == $Obj['ObjectType'] ) // is variable?
		{
		   $Var = IPS_GetVariable( $VarID );
		   if ( $Type == $Var['VariableValue']['ValueType'] )
			{
			   SetVariable( $VarID, $Type, $Value );
			   return;
			}
		}
	}
	$VarID = IPS_CreateVariable( $Type );
	IPS_SetParent( $VarID, $ParentID );
	IPS_SetName( $VarID, $Name );
	if ( '' != $Ident )
	   IPS_SetIdent( $VarID, $Ident );
	SetVariable( $VarID, $Type, $Value );
}

?>
